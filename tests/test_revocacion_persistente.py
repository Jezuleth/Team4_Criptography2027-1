"""Firma obligatoria, orden firma -> llave, revocación persistente y retiro
de la llave del repositorio (keystore en disco)."""

import base64
import json
import os
import stat

import pytest

from vault.integrated_vault import (
    ARCHIVO_ECIES,
    crear_identidad,
    enviar_archivo,
    recibir_archivo,
    recuperar_identidad,
    registrar_identidad_en_gestor,
    revocar_identidad,
)
from vault.key_lifecycle import ErrorCicloVida, GestorCicloVida
from vault.keystore import ErrorKeystore, eliminar_keystore
from vault.signatures import (
    CAMPOS_FIRMA,
    ErrorFirma,
    digest_a_firmar,
    generar_par_claves_firma,
    huella_clave_firma,
    verificar_contenedor,
)
from vault.signed_sharing import abrir_archivo_firmado, cifrar_y_firmar
from vault.sharing import abrir_archivo_compartido

PASSWORD = "contraseña-de-prueba-123"
PASSWORD_ESTADO = "historial-de-prueba-123"


@pytest.fixture
def escenario(tmp_path):
    """alice envía a bob; todo en disco, con un archivo .vault firmado."""
    alice = crear_identidad("alice", PASSWORD, tmp_path / "alice")
    bob = crear_identidad("bob", PASSWORD, tmp_path / "bob")
    origen = tmp_path / "doc.txt"
    origen.write_bytes(b"documento secreto")
    vault = tmp_path / "doc.vault"
    enviar_archivo(
        origen, vault, {"bob": bob["clave_publica_ecies"]},
        tmp_path / "alice", PASSWORD,
    )
    ruta_estado = tmp_path / "historial.enc"
    gestor = GestorCicloVida(ruta_estado, PASSWORD_ESTADO)
    registrar_identidad_en_gestor("bob", tmp_path / "bob", PASSWORD, gestor)
    return {
        "dir": tmp_path, "vault": vault, "alice": alice, "bob": bob,
        "gestor": gestor, "ruta_estado": ruta_estado,
    }


def _recibir(e, gestor=None, vault=None):
    return recibir_archivo(
        vault or e["vault"], e["dir"] / "salida.txt", "bob",
        e["dir"] / "bob", PASSWORD, e["alice"]["clave_publica_firma"],
        gestor or e["gestor"],
    )


# ---- 1. Sin firma no se descifra -------------------------------------------
def test_flujo_normal_descifra(escenario):
    assert _recibir(escenario) == b"documento secreto"


def test_sin_firma_no_se_descifra(escenario):
    e = escenario
    c = json.loads(e["vault"].read_text())
    for campo in CAMPOS_FIRMA:
        c.pop(campo)
    sin_firma = e["dir"] / "sin_firma.vault"
    sin_firma.write_text(json.dumps(c))
    with pytest.raises(ErrorFirma):
        _recibir(e, vault=sin_firma)
    assert not (e["dir"] / "salida.txt").exists()


def test_gestor_obligatorio_en_ruta_firmada(escenario):
    e = escenario
    bob = recuperar_identidad(PASSWORD, e["dir"] / "bob")["clave_ecies"]
    with pytest.raises(TypeError):
        abrir_archivo_firmado(
            e["vault"], bob, "bob", e["alice"]["clave_publica_firma"]
        )
    with pytest.raises(ValueError):
        abrir_archivo_firmado(
            e["vault"], bob, "bob", e["alice"]["clave_publica_firma"], None
        )


def test_contenedor_firmado_no_abre_por_ruta_sin_firma(escenario):
    """D3 directo rechaza campos de firma: no sirve para saltarse D5."""
    e = escenario
    bob = recuperar_identidad(PASSWORD, e["dir"] / "bob")["clave_ecies"]
    with pytest.raises(Exception):
        abrir_archivo_compartido(e["vault"], bob, id_usuario="bob")


# ---- 2. Firma completa y luego llave con hash completo ---------------------
def _refirmar(contenedor, firmante, **cambios):
    """Contenedor con campos alterados y una firma VÁLIDA sobre ellos."""
    c = {k: v for k, v in contenedor.items() if k != "signature"}
    c.update(cambios)
    c["signature"] = base64.b64encode(firmante.sign(digest_a_firmar(c))).decode()
    return c


@pytest.fixture
def firmado(alice, bob):
    firmante = generar_par_claves_firma()
    c = cifrar_y_firmar(
        b"x", "a.txt", {"alice": alice.public_key(), "bob": bob.public_key()},
        firmante,
    )
    return c, firmante


@pytest.mark.parametrize("recorte", [32, 63])
def test_huella_truncada_rechazada_aunque_la_firma_sea_valida(firmado, recorte):
    c, firmante = firmado
    completo = huella_clave_firma(firmante.public_key())
    malo = _refirmar(c, firmante, signer_id=completo[:recorte])
    with pytest.raises(ErrorFirma):
        verificar_contenedor(malo, firmante.public_key())


def test_huella_en_mayusculas_rechazada(firmado):
    c, firmante = firmado
    malo = _refirmar(
        c, firmante, signer_id=huella_clave_firma(firmante.public_key()).upper()
    )
    with pytest.raises(ErrorFirma):
        verificar_contenedor(malo, firmante.public_key())


def test_firma_truncada_rechazada(firmado):
    c, firmante = firmado
    corta = base64.b64encode(
        base64.b64decode(c["signature"])[:63]
    ).decode()
    with pytest.raises(ErrorFirma):
        verificar_contenedor({**c, "signature": corta}, firmante.public_key())


def test_firma_valida_de_otra_llave_con_signer_id_ajeno_rechazada(firmado):
    """Firma válida de un atacante que declara la huella de la víctima."""
    c, victima = firmado
    atacante = generar_par_claves_firma()
    falso = _refirmar(
        c, atacante, signer_id=huella_clave_firma(victima.public_key())
    )
    with pytest.raises(ErrorFirma):
        verificar_contenedor(falso, victima.public_key())


def test_orden_firma_antes_que_llave(firmado, monkeypatch):
    """La huella solo se evalúa si la firma criptográfica ya fue válida."""
    c, firmante = firmado
    llamadas = []
    import vault.signatures as m

    original = m._verificar_huella_firmante
    monkeypatch.setattr(
        m, "_verificar_huella_firmante",
        lambda *a: (llamadas.append(1), original(*a))[1],
    )
    alterado = {**c, "signature": base64.b64encode(bytes(64)).decode()}
    with pytest.raises(ErrorFirma):
        verificar_contenedor(alterado, firmante.public_key())
    assert llamadas == []  # firma inválida: ni se llegó a la llave
    verificar_contenedor(c, firmante.public_key())
    assert llamadas == [1]


# ---- 3. Revocación persistente en disco ------------------------------------
def test_revocacion_sobrevive_al_reinicio(escenario):
    e = escenario
    revocar_identidad("bob", e["dir"] / "bob", e["gestor"], "compromiso")
    reiniciado = GestorCicloVida(e["ruta_estado"], PASSWORD_ESTADO)
    assert reiniciado.obtener_registro("bob").estado == "revocada"
    assert reiniciado.obtener_registro("bob").motivo_revocacion == "compromiso"


def test_clave_revocada_no_descifra_aunque_se_conserve_en_memoria(escenario):
    e = escenario
    bob = recuperar_identidad(PASSWORD, e["dir"] / "bob")["clave_ecies"]
    revocar_identidad("bob", e["dir"] / "bob", e["gestor"], "compromiso")
    reiniciado = GestorCicloVida(e["ruta_estado"], PASSWORD_ESTADO)
    with pytest.raises(ErrorCicloVida):
        abrir_archivo_firmado(
            e["vault"], bob, "bob", e["alice"]["clave_publica_firma"],
            reiniciado,
        )


def test_estado_en_disco_con_permisos_privados_y_sin_temporales(escenario):
    e = escenario
    revocar_identidad("bob", e["dir"] / "bob", e["gestor"], "compromiso")
    if os.name == "posix":
        assert stat.S_IMODE(e["ruta_estado"].stat().st_mode) == 0o600
    assert not list(e["dir"].glob("historial.enc.*.tmp"))


def test_fallo_al_persistir_avisa_y_deja_revocada_en_memoria(escenario, monkeypatch):
    e = escenario

    def falla(self, datos):
        raise OSError("disco lleno")

    monkeypatch.setattr(GestorCicloVida, "_escribir_duradero", falla)
    with pytest.raises(ErrorCicloVida, match="no se pudo guardar"):
        e["gestor"].revocar_clave("bob", "compromiso")
    assert e["gestor"].obtener_registro("bob").estado == "revocada"


# ---- 4. La llave sale del repositorio (keystore en disco) ------------------
def test_revocar_elimina_el_keystore(escenario):
    e = escenario
    ruta = e["dir"] / "bob" / ARCHIVO_ECIES
    assert ruta.exists()
    assert revocar_identidad("bob", e["dir"] / "bob", e["gestor"], "baja") is True
    assert not ruta.exists()
    with pytest.raises(ErrorKeystore):
        recuperar_identidad(PASSWORD, e["dir"] / "bob")
    with pytest.raises(Exception):
        _recibir(e)


def test_revocar_no_toca_a_otros_usuarios(escenario):
    e = escenario
    revocar_identidad("bob", e["dir"] / "bob", e["gestor"], "baja")
    assert (e["dir"] / "alice" / ARCHIVO_ECIES).exists()
    recuperar_identidad(PASSWORD, e["dir"] / "alice")


def test_eliminar_keystore_inexistente_devuelve_false(tmp_path):
    assert eliminar_keystore(tmp_path / "no_existe.keystore") is False


def test_revocar_usuario_no_registrado_no_borra_nada(escenario):
    e = escenario
    with pytest.raises(ErrorCicloVida):
        revocar_identidad("alice", e["dir"] / "alice", e["gestor"], "baja")
    assert (e["dir"] / "alice" / ARCHIVO_ECIES).exists()

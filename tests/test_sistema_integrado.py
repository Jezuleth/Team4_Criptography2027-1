"""Sistema integrado final: directorio público, revocación del firmante,
retiro completo del repositorio de llaves y ataques del laboratorio."""

import json

import pytest

from vault import ataques
from vault.integrated_vault import (
    ARCHIVO_ECIES,
    ARCHIVO_FIRMA,
    ARCHIVO_HISTORIAL,
    ARCHIVO_PUBLICO,
    DirectorioAlterado,
    abrir_gestor,
    cargar_identidad_publica,
    crear_identidad,
    enviar_archivo_con_claves,
    identificar_remitente,
    listar_identidades,
    recuperar_identidad,
    resumen_identidad,
    revocar_identidad,
)
from vault.key_lifecycle import ErrorCicloVida, FirmanteRevocado
from vault.public_key import DestinatarioNoAutorizado
from vault.sharing import compartir_archivo
from vault.signatures import ErrorFirma
from vault.signed_sharing import (
    abrir_archivo_firmado,
    descifrar_contenedor_firmado,
    leer_contenedor,
)

PASSWORD = "contraseña-de-prueba-123"
HISTORIAL = "historial-de-prueba-123"


@pytest.fixture
def sistema(tmp_path):
    base = tmp_path / "identidades"
    gestor = abrir_gestor(base, HISTORIAL)
    for usuario in ("alice", "bob", "carol", "mallory"):
        crear_identidad(usuario, PASSWORD, base / usuario, gestor)
    claves = {u: recuperar_identidad(PASSWORD, base / u) for u in ("alice", "bob", "carol", "mallory")}
    origen = tmp_path / "doc.txt"
    origen.write_bytes(b"documento integrado")
    vault = tmp_path / "doc.vault"
    publicas = {u: cargar_identidad_publica(base / u, gestor) for u in ("bob", "carol")}
    enviar_archivo_con_claves(
        origen, vault,
        {u: p["clave_publica_ecies"] for u, p in publicas.items()},
        claves["alice"]["clave_firma"], gestor,
    )
    return {"base": base, "gestor": gestor, "claves": claves, "vault": vault, "dir": tmp_path}


def _abrir(s, usuario, contenedor=None, gestor=None):
    contenedor = contenedor or leer_contenedor(s["vault"])
    remitente = identificar_remitente(contenedor, s["base"], gestor or s["gestor"])
    return descifrar_contenedor_firmado(
        contenedor, s["claves"][usuario]["clave_ecies"], usuario,
        remitente["clave_publica_firma"], gestor or s["gestor"],
    )


# ---- Directorio y flujo normal ---------------------------------------------
def test_listar_y_flujo_normal(sistema):
    assert listar_identidades(sistema["base"]) == ["alice", "bob", "carol", "mallory"]
    assert _abrir(sistema, "bob") == b"documento integrado"
    assert _abrir(sistema, "carol") == b"documento integrado"


def test_remitente_identificado_por_signer_id(sistema):
    c = leer_contenedor(sistema["vault"])
    assert identificar_remitente(c, sistema["base"])["usuario"] == "alice"


def test_nombre_usuario_invalido(tmp_path):
    for malo in ("", "Alice", "../x", "a b", "x" * 33):
        with pytest.raises(ValueError):
            crear_identidad(malo, PASSWORD, tmp_path / "x")


def test_directorio_sustituido_detectado(sistema):
    """Cambiar la clave pública de bob por la de mallory se detecta."""
    ruta = sistema["base"] / "bob" / ARCHIVO_PUBLICO
    mallory = json.loads((sistema["base"] / "mallory" / ARCHIVO_PUBLICO).read_text())
    falso = {**mallory, "usuario": "bob"}
    ruta.write_text(json.dumps(falso))
    with pytest.raises(DirectorioAlterado):
        cargar_identidad_publica(sistema["base"] / "bob", sistema["gestor"])


def test_directorio_incoherente_detectado(sistema):
    ruta = sistema["base"] / "bob" / ARCHIVO_PUBLICO
    datos = json.loads(ruta.read_text())
    datos["huella_firma"] = "0" * 64
    ruta.write_text(json.dumps(datos))
    with pytest.raises(DirectorioAlterado):
        cargar_identidad_publica(sistema["base"] / "bob")


# ---- Sin firma no se descifra ----------------------------------------------
def test_archivo_d3_sin_firma_rechazado(sistema):
    sin_firma = sistema["dir"] / "d3.vault"
    compartir_archivo(
        sistema["dir"] / "doc.txt", sin_firma,
        {"bob": sistema["claves"]["bob"]["clave_ecies"].public_key()},
    )
    c = leer_contenedor(sin_firma)
    with pytest.raises(ErrorFirma, match="no está firmado"):
        identificar_remitente(c, sistema["base"])
    alice_pub = cargar_identidad_publica(sistema["base"] / "alice")["clave_publica_firma"]
    with pytest.raises(ErrorFirma):
        abrir_archivo_firmado(
            sin_firma, sistema["claves"]["bob"]["clave_ecies"], "bob",
            alice_pub, sistema["gestor"],
        )


@pytest.mark.parametrize("clave,_t,_d,ataque", ataques.CATALOGO)
def test_ataques_del_laboratorio_rechazados(sistema, clave, _t, _d, ataque):
    original = leer_contenedor(sistema["vault"])
    alterado = ataque(original)
    alice_pub = cargar_identidad_publica(sistema["base"] / "alice")["clave_publica_firma"]
    with pytest.raises(ErrorFirma):
        descifrar_contenedor_firmado(
            alterado, sistema["claves"]["bob"]["clave_ecies"], "bob",
            alice_pub, sistema["gestor"],
        )
    assert original == leer_contenedor(sistema["vault"])  # el original no cambia


def test_mallory_no_destinataria(sistema):
    with pytest.raises(DestinatarioNoAutorizado):
        _abrir(sistema, "mallory")


# ---- Revocación persistente y retiro del repositorio -----------------------
def test_revocar_retira_ambos_keystores_y_persiste(sistema):
    base, gestor = sistema["base"], sistema["gestor"]
    assert revocar_identidad("bob", base / "bob", gestor, "compromiso") is True
    assert not (base / "bob" / ARCHIVO_ECIES).exists()
    assert not (base / "bob" / ARCHIVO_FIRMA).exists()
    assert (base / "bob" / ARCHIVO_PUBLICO).exists()

    reiniciado = abrir_gestor(base, HISTORIAL)
    resumen = resumen_identidad("bob", base, reiniciado)
    assert resumen["estado"] == "revocada"
    assert resumen["llaves_en_repositorio"] is False
    with pytest.raises(ErrorCicloVida):
        _abrir(sistema, "bob", gestor=reiniciado)
    assert _abrir(sistema, "carol", gestor=reiniciado) == b"documento integrado"


def test_no_se_cifra_para_identidad_revocada(sistema):
    base, gestor = sistema["base"], sistema["gestor"]
    bob_pub = cargar_identidad_publica(base / "bob", gestor)["clave_publica_ecies"]
    revocar_identidad("bob", base / "bob", gestor, "compromiso")
    with pytest.raises(ErrorCicloVida):
        enviar_archivo_con_claves(
            sistema["dir"] / "doc.txt", sistema["dir"] / "otro.vault",
            {"bob": bob_pub}, sistema["claves"]["alice"]["clave_firma"], gestor,
        )
    assert not (sistema["dir"] / "otro.vault").exists()


def test_firmante_revocado_rechazado_tras_reinicio(sistema):
    base = sistema["base"]
    revocar_identidad("alice", base / "alice", sistema["gestor"], "compromiso")
    reiniciado = abrir_gestor(base, HISTORIAL)
    with pytest.raises(FirmanteRevocado):
        _abrir(sistema, "carol", gestor=reiniciado)
    with pytest.raises(FirmanteRevocado):
        enviar_archivo_con_claves(
            sistema["dir"] / "doc.txt", sistema["dir"] / "x.vault",
            {"carol": sistema["claves"]["carol"]["clave_ecies"].public_key()},
            sistema["claves"]["alice"]["clave_firma"], reiniciado,
        )


def test_clave_revocada_no_puede_reregistrarse(sistema):
    """Restaurar la clave (p. ej. desde un respaldo) no la reactiva."""
    base = sistema["base"]
    bob = sistema["claves"]["bob"]["clave_ecies"]
    revocar_identidad("bob", base / "bob", sistema["gestor"], "compromiso")
    reiniciado = abrir_gestor(base, HISTORIAL)
    with pytest.raises(ErrorCicloVida, match="revocada"):
        reiniciado.registrar_clave_existente("bob2", bob)


def test_historial_conserva_versiones_rotadas():
    from vault.key_lifecycle import GestorCicloVida

    gestor = GestorCicloVida()
    _, r1 = gestor.generar_clave("alice")
    gestor.rotar_clave("alice")
    historial = gestor.obtener_historial("alice")
    assert [h["fingerprint"] for h in historial] == [r1.fingerprint]
    assert historial[0]["estado"] == "rotada"


def test_historial_nuevo_exige_contrasena_robusta(tmp_path):
    with pytest.raises(ErrorCicloVida):
        abrir_gestor(tmp_path, "corta")
    gestor = abrir_gestor(tmp_path, HISTORIAL)
    gestor.generar_clave("alice")
    assert (tmp_path / ARCHIVO_HISTORIAL).exists()
    with pytest.raises(ErrorCicloVida, match="Contraseña incorrecta"):
        abrir_gestor(tmp_path, "otra-contraseña-123")

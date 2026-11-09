"""D5 - Pruebas de integración: Encrypt -> Sign -> Store / Verify -> Decrypt.

Usa las fixtures de conftest.py: alice, bob, mallory (claves ECIES) y contenido.
"""

import copy
import json

import pytest

from vault import signed_sharing
from vault.public_key import DestinatarioNoAutorizado
from vault.shared_container import ContenedorInvalido
from vault.sharing import descifrar_como_destinatario
from vault.signatures import ErrorFirma, generar_par_claves_firma
from vault.signed_sharing import (
    abrir_archivo_firmado,
    cifrar_y_firmar,
    descifrar_contenedor_firmado,
    firmar_y_compartir_archivo,
    verificar_archivo_firmado,
)


@pytest.fixture(scope="session")
def firmante():
    return generar_par_claves_firma()


@pytest.fixture
def firmado(alice, bob, contenido, firmante):
    return cifrar_y_firmar(
        contenido,
        "contrato.txt",
        {"alice": alice.public_key(), "bob": bob.public_key()},
        firmante,
    )


def _cambiar_texto(s):
    """Altera un carácter del texto (independiente de la codificación)."""
    return s[:-2] + ("A" if s[-2] != "A" else "B") + s[-1]


def _abrir(contenedor, usuario, nombre, firmante):
    return descifrar_contenedor_firmado(
        contenedor, usuario, nombre, firmante.public_key()
    )


# ---- Los 5 casos obligatorios --------------------------------------------
def test_1_firma_valida_archivo_aceptado(firmado, alice, bob, firmante, contenido):
    assert _abrir(firmado, alice, "alice", firmante) == contenido
    assert _abrir(firmado, bob, "bob", firmante) == contenido


def test_2_ciphertext_modificado_rechazado(firmado, alice, firmante):
    firmado["ciphertext"] = _cambiar_texto(firmado["ciphertext"])
    with pytest.raises(ErrorFirma):
        _abrir(firmado, alice, "alice", firmante)


def test_3_metadatos_modificados_rechazados(firmado, alice, firmante):
    firmado["header"]["nombre_archivo"] = "otro.txt"
    with pytest.raises(ErrorFirma):
        _abrir(firmado, alice, "alice", firmante)


def test_4_clave_publica_incorrecta_rechazada(firmado, alice):
    with pytest.raises(ErrorFirma):
        descifrar_contenedor_firmado(
            firmado, alice, "alice", generar_par_claves_firma().public_key()
        )


def test_5_firma_eliminada_rechazada(firmado, alice, firmante):
    del firmado["signature"]
    with pytest.raises(ErrorFirma):
        _abrir(firmado, alice, "alice", firmante)


# ---- Cobertura de todo lo que se firma -----------------------------------
@pytest.mark.parametrize("campo", ["nonce", "tag"])
def test_nonce_o_tag_modificado(firmado, firmante, campo):
    firmado[campo] = _cambiar_texto(firmado[campo])
    with pytest.raises(ErrorFirma):
        signed_sharing.verificar_contenedor_firmado(firmado, firmante.public_key())


@pytest.mark.parametrize(
    "campo",
    ["fecha", "algoritmo", "algoritmo_envoltura", "algoritmo_huella", "id_archivo"],
)
def test_cualquier_campo_del_header_modificado(firmado, firmante, campo):
    firmado["header"][campo] = _cambiar_texto(str(firmado["header"][campo]))
    with pytest.raises(ErrorFirma):
        signed_sharing.verificar_contenedor_firmado(firmado, firmante.public_key())


def test_destinatario_agregado(firmado, firmante, mallory):
    from vault.public_key import huella_clave_publica

    nuevo = copy.deepcopy(firmado["recipients"][0])
    nuevo["id"] = "mallory"
    nuevo["key_id"] = huella_clave_publica(mallory.public_key())
    firmado["recipients"].append(nuevo)
    with pytest.raises(ErrorFirma):
        signed_sharing.verificar_contenedor_firmado(firmado, firmante.public_key())


def test_destinatario_eliminado(firmado, firmante):
    firmado["recipients"].pop()
    with pytest.raises(ErrorFirma):
        signed_sharing.verificar_contenedor_firmado(firmado, firmante.public_key())


def test_destinatarios_reordenados(firmado, firmante):
    firmado["recipients"].reverse()
    with pytest.raises(ErrorFirma):
        signed_sharing.verificar_contenedor_firmado(firmado, firmante.public_key())


def test_clave_envuelta_modificada(firmado, firmante):
    firmado["recipients"][0]["encrypted_key"] = _cambiar_texto(
        firmado["recipients"][0]["encrypted_key"]
    )
    with pytest.raises(ErrorFirma):
        signed_sharing.verificar_contenedor_firmado(firmado, firmante.public_key())


# ---- Falsificación y orden de operaciones --------------------------------
def test_falsificacion_mallory_refirma(firmado, alice, firmante):
    """Mallory re-firma el mismo contenedor con su clave y lo presenta como
    si viniera del firmante legítimo: se rechaza."""
    interno = signed_sharing.verificar_contenedor_firmado(firmado, firmante.public_key())
    mallory_firma = generar_par_claves_firma()
    falso = signed_sharing.firmar_contenedor_compartido(interno, mallory_firma)
    with pytest.raises(ErrorFirma):
        _abrir(falso, alice, "alice", firmante)


def test_reencriptar_contenido_y_afirmar_autoria_falla(alice, firmante, contenido):
    """Sin la clave privada de firma, re-cifrar el contenido no da autoría."""
    atacante = generar_par_claves_firma()
    falso = cifrar_y_firmar(contenido, "contrato.txt", {"alice": alice.public_key()}, atacante)
    with pytest.raises(ErrorFirma):
        _abrir(falso, alice, "alice", firmante)


def test_verifica_antes_de_descifrar(firmado, alice, firmante, monkeypatch):
    def no_debe_llamarse(*a, **k):
        raise AssertionError("se intentó descifrar sin verificar la firma")

    monkeypatch.setattr(signed_sharing, "descifrar_como_destinatario", no_debe_llamarse)
    firmado["header"]["nombre_archivo"] = "x.txt"
    with pytest.raises(ErrorFirma):
        _abrir(firmado, alice, "alice", firmante)


def test_d3_no_abre_un_contenedor_firmado_directamente(firmado, alice):
    """Los campos de firma hacen que D3 lo rechace: no hay atajo sin verificar."""
    with pytest.raises(ContenedorInvalido):
        descifrar_como_destinatario(firmado, alice, "alice")


def test_firma_valida_pero_mallory_no_es_destinataria(firmado, mallory, firmante):
    """Autenticidad ok; el control de acceso de D3 sigue funcionando."""
    with pytest.raises(DestinatarioNoAutorizado):
        _abrir(firmado, mallory, "mallory", firmante)


def test_firma_valida_pero_usuario_suplantado(firmado, alice, firmante):
    with pytest.raises(DestinatarioNoAutorizado):
        _abrir(firmado, alice, "bob", firmante)


def test_no_se_firma_un_contenedor_v3_invalido(firmante):
    with pytest.raises(ContenedorInvalido):
        signed_sharing.firmar_contenedor_compartido({"header": {}}, firmante)


# ---- Archivos en disco ---------------------------------------------------
@pytest.fixture
def vault_en_disco(tmp_path, alice, bob, firmante, contenido):
    origen = tmp_path / "contrato.txt"
    origen.write_bytes(contenido)
    ruta = tmp_path / "contrato.vault"
    firmar_y_compartir_archivo(
        origen, ruta, {"alice": alice.public_key(), "bob": bob.public_key()}, firmante
    )
    return ruta


def test_disco_ida_y_vuelta(vault_en_disco, bob, firmante, contenido, tmp_path):
    salida = tmp_path / "recuperado.txt"
    datos = abrir_archivo_firmado(
        vault_en_disco, bob, "bob", firmante.public_key(), ruta_salida=salida
    )
    assert datos == contenido == salida.read_bytes()


def test_disco_contiene_campos_requeridos(vault_en_disco):
    d = json.loads(vault_en_disco.read_text(encoding="utf-8"))
    assert set(d) == {"header", "recipients", "nonce", "ciphertext", "tag",
                      "signature", "signer_id", "signature_algorithm"}


def test_disco_modificado_en_bytes(vault_en_disco, alice, firmante):
    d = json.loads(vault_en_disco.read_text(encoding="utf-8"))
    d["ciphertext"] = _cambiar_texto(d["ciphertext"])
    vault_en_disco.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ErrorFirma):
        abrir_archivo_firmado(vault_en_disco, alice, "alice", firmante.public_key())


def test_disco_firma_eliminada(vault_en_disco, alice, firmante):
    d = json.loads(vault_en_disco.read_text(encoding="utf-8"))
    del d["signature"], d["signer_id"], d["signature_algorithm"]
    vault_en_disco.write_text(json.dumps(d), encoding="utf-8")
    with pytest.raises(ErrorFirma):
        abrir_archivo_firmado(vault_en_disco, alice, "alice", firmante.public_key())


def test_disco_claves_json_duplicadas(vault_en_disco, firmante):
    texto = vault_en_disco.read_text(encoding="utf-8").rstrip()
    vault_en_disco.write_text(texto[:-1] + ', "tag": "x"}', encoding="utf-8")
    with pytest.raises(ErrorFirma):
        verificar_archivo_firmado(vault_en_disco, firmante.public_key())


@pytest.mark.parametrize("contenido_malo", ["", "no es json", "[]", "null", '{"a": NaN}'])
def test_disco_archivo_malformado(vault_en_disco, firmante, contenido_malo):
    vault_en_disco.write_text(contenido_malo, encoding="utf-8")
    with pytest.raises(ErrorFirma):
        verificar_archivo_firmado(vault_en_disco, firmante.public_key())


def test_disco_archivo_inexistente(tmp_path, firmante):
    with pytest.raises(ErrorFirma):
        verificar_archivo_firmado(tmp_path / "no_existe.vault", firmante.public_key())
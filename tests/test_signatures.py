"""D5 - Pruebas de las primitivas de firma (vault/signatures.py)."""

import copy
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from vault.signatures import (
    ALGORITMO_FIRMA,
    ErrorFirma,
    exportar_clave_privada_firma,
    exportar_clave_publica_firma,
    firmar_contenedor,
    generar_par_claves_firma,
    huella_clave_firma,
    importar_clave_privada_firma,
    importar_clave_publica_firma,
    verificar_contenedor,
)


@pytest.fixture
def contenedor():
    return {
        "header": {"nombre_archivo": "a.pdf", "version": 3, "id_archivo": "x"},
        "recipients": [{"id": "alice", "key_id": "k1", "encrypted_key": "QQ=="}],
        "nonce": "bm9uY2U=",
        "ciphertext": "Y2lwaGVy",
        "tag": "dGFn",
    }


@pytest.fixture
def firmante():
    return generar_par_claves_firma()


def test_firma_valida(contenedor, firmante):
    f = firmar_contenedor(contenedor, firmante)
    verificar_contenedor(f, firmante.public_key())
    assert f["signature_algorithm"] == ALGORITMO_FIRMA
    assert f["signer_id"] == huella_clave_firma(firmante.public_key())


def test_firmar_no_muta_el_original(contenedor, firmante):
    original = copy.deepcopy(contenedor)
    firmar_contenedor(contenedor, firmante)
    assert contenedor == original


def test_no_se_firma_dos_veces(contenedor, firmante):
    with pytest.raises(ErrorFirma):
        firmar_contenedor(firmar_contenedor(contenedor, firmante), firmante)


def test_huella_estable_y_distinta_por_clave(firmante):
    h = huella_clave_firma(firmante.public_key())
    assert h == huella_clave_firma(firmante.public_key())
    assert len(h) == 64
    assert h != huella_clave_firma(generar_par_claves_firma().public_key())


@pytest.mark.parametrize(
    "mutar",
    [
        lambda c: c["header"].update(nombre_archivo="otro.pdf"),
        lambda c: c["header"].update(version=4),
        lambda c: c["recipients"].append({"id": "mallory", "key_id": "k9", "encrypted_key": "QQ=="}),
        lambda c: c["recipients"][0].update(id="bob"),
        lambda c: c["recipients"].reverse() or c["recipients"].append(c["recipients"][0]),
        lambda c: c.update(nonce="bm9uY2Uy"),
        lambda c: c.update(ciphertext="Y2lwaGVyMg=="),
        lambda c: c.update(tag="dGFnMg=="),
        lambda c: c.update(campo_extra="x"),
        lambda c: c.update(signer_id="0" * 64),
    ],
)
def test_cualquier_modificacion_se_rechaza(contenedor, firmante, mutar):
    f = firmar_contenedor(contenedor, firmante)
    mutar(f)
    with pytest.raises(ErrorFirma):
        verificar_contenedor(f, firmante.public_key())


def test_clave_publica_incorrecta(contenedor, firmante):
    f = firmar_contenedor(contenedor, firmante)
    with pytest.raises(ErrorFirma):
        verificar_contenedor(f, generar_par_claves_firma().public_key())


def test_falsificacion_refirmada_por_atacante(contenedor, firmante):
    """Mallory re-firma con su clave: no es aceptado como Alice."""
    mallory = generar_par_claves_firma()
    falso = firmar_contenedor(contenedor, mallory)
    with pytest.raises(ErrorFirma):
        verificar_contenedor(falso, firmante.public_key())
    verificar_contenedor(falso, mallory.public_key())  # válido como Mallory


@pytest.mark.parametrize("campo", ["signature", "signer_id", "signature_algorithm"])
def test_campo_de_firma_eliminado(contenedor, firmante, campo):
    f = firmar_contenedor(contenedor, firmante)
    del f[campo]
    with pytest.raises(ErrorFirma):
        verificar_contenedor(f, firmante.public_key())


@pytest.mark.parametrize("valor", ["", "!!!", "QUJD", 123, None, "A" * 88])
def test_firma_malformada(contenedor, firmante, valor):
    f = firmar_contenedor(contenedor, firmante)
    f["signature"] = valor
    with pytest.raises(ErrorFirma):
        verificar_contenedor(f, firmante.public_key())


def test_downgrade_de_algoritmo(contenedor, firmante):
    f = firmar_contenedor(contenedor, firmante)
    f["signature_algorithm"] = "NONE"
    with pytest.raises(ErrorFirma):
        verificar_contenedor(f, firmante.public_key())


def test_contenedor_no_dict(firmante):
    with pytest.raises(ErrorFirma):
        verificar_contenedor([], firmante.public_key())


def test_roundtrip_pem(firmante):
    pem = exportar_clave_privada_firma(firmante, b"pw-segura")
    assert b"ENCRYPTED" in pem
    assert importar_clave_privada_firma(pem, b"pw-segura").public_key().public_bytes_raw() == \
        firmante.public_key().public_bytes_raw()
    with pytest.raises(ErrorFirma):
        importar_clave_privada_firma(pem, b"incorrecta")
    pub = exportar_clave_publica_firma(firmante.public_key())
    assert huella_clave_firma(importar_clave_publica_firma(pub)) == \
        huella_clave_firma(firmante.public_key())


def test_rechaza_otros_tipos_de_clave(contenedor):
    p256 = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ErrorFirma):
        firmar_contenedor(contenedor, p256)
    with pytest.raises(ErrorFirma):
        huella_clave_firma(p256.public_key())
    with pytest.raises(ErrorFirma):
        exportar_clave_privada_firma(generar_par_claves_firma(), b"")

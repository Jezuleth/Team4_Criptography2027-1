
import os
import pytest

from vault.encryption import cifrar_archivo


def test_cifrado_exitoso():
    datos = b"Archivo secreto del D2"
    clave = os.urandom(32)
    nonce = os.urandom(12)

    resultado = cifrar_archivo(datos, clave, nonce, b"metadatos")

    assert resultado != datos
    assert len(resultado) == len(datos) + 16


def test_clave_incorrecta():
    datos = b"Archivo secreto"
    clave = os.urandom(16)
    nonce = os.urandom(12)

    with pytest.raises(ValueError):
        cifrar_archivo(datos, clave, nonce, b"metadatos")


def test_nonce_incorrecto():
    datos = b"Archivo secreto"
    clave = os.urandom(32)
    nonce = os.urandom(8)

    with pytest.raises(ValueError):
        cifrar_archivo(datos, clave, nonce, b"metadatos")

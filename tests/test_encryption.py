
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

def test_cifrar_con_contraseña():
    from vault.encryption import cifrar_con_contraseña
    from vault.key_management import recuperar_clave
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    datos = b"Archivo secreto del D2"
    contraseña = "MiClave123"
    aad = b"metadata-test"

    # Cifrar usando ambos modulos
    resultado = cifrar_con_contraseña(datos, contraseña, aad)

    # Recuperar la clave usando la funcion de Javier
    clave = recuperar_clave(
        resultado["clave_protegida"],
        contraseña
    )

    # Comprobar que los datos originales se recuperan
    aesgcm = AESGCM(clave)
    datos_recuperados = aesgcm.decrypt(
        resultado["nonce"],
        resultado["datos_cifrados"],
        aad
    )

    assert datos_recuperados == datos

def test_detectar_metadatos_modificados():
    import pytest
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from vault.encryption import cifrar_con_contraseña
    from vault.key_management import recuperar_clave

    datos = b"Archivo secreto del D2"
    contraseña = "MiClave123"
    aad_original = b"nombre=archivo.txt"

    resultado = cifrar_con_contraseña(
        datos, contraseña, aad_original
    )

    clave = recuperar_clave(
        resultado["clave_protegida"], contraseña
    )

    # Intentar descifrar con metadatos modificados
    aad_modificado = b"nombre=archivo_modificado.txt"

    with pytest.raises(InvalidTag):
        AESGCM(clave).decrypt(
            resultado["nonce"],
            resultado["datos_cifrados"],
            aad_modificado
        )

def test_cifrados_independientes():
    from vault.encryption import cifrar_con_contraseña
    from vault.key_management import recuperar_clave

    datos = b"Archivo secreto del D2"
    contraseña = "MiClave123"
    aad = b"metadata-test"

    resultado1 = cifrar_con_contraseña(datos, contraseña, aad)
    resultado2 = cifrar_con_contraseña(datos, contraseña, aad)

    clave1 = recuperar_clave(resultado1["clave_protegida"], contraseña)
    clave2 = recuperar_clave(resultado2["clave_protegida"], contraseña)

    assert clave1 != clave2
    assert resultado1["nonce"] != resultado2["nonce"]
    assert resultado1["datos_cifrados"] != resultado2["datos_cifrados"]

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def cifrar_archivo(datos: bytes, clave_archivo: bytes, nonce: bytes, aad: bytes) -> bytes:
    """
    Cifra el contenido de un archivo utilizando AES-256-GCM.

    datos: contenido original del archivo.
    clave_archivo: clave de 32 bytes generada por el módulo de Javier.
    nonce: valor de 12 bytes, único para esta clave.
    aad: metadatos que se autenticarán sin cifrarse.

    Devuelve el contenido cifrado con su etiqueta de autenticación.
    """
    if len(clave_archivo) != 32:
        raise ValueError("La clave debe tener 32 bytes.")

    if len(nonce) != 12:
        raise ValueError("El nonce debe tener 12 bytes.")

    aesgcm = AESGCM(clave_archivo)
    ciphertext = aesgcm.encrypt(nonce, datos, aad)

    return ciphertext

from vault.key_management import (
    generar_clave_archivo,
    generar_nonce,
    proteger_clave
)


def cifrar_con_contraseña(datos: bytes, contraseña: str, aad: bytes) -> dict:
    """
    Cifra datos con una clave AES-256 nueva y
    protege esa clave usando una contraseña.
    """
    clave_archivo = generar_clave_archivo()
    nonce = generar_nonce()

    datos_cifrados = cifrar_archivo(
        datos,
        clave_archivo,
        nonce,
        aad
    )

    clave_protegida = proteger_clave(
        clave_archivo,
        contraseña
    )

    return {
        "nonce": nonce,
        "datos_cifrados": datos_cifrados,
        "clave_protegida": clave_protegida
    }

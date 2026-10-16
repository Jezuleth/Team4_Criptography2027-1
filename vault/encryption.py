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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.key_management import recuperar_clave
from vault.container import serializar_metadatos, leer_contenedor


def descifrar_archivo(
    datos_cifrados: bytes,
    clave_archivo: bytes,
    nonce: bytes,
    aad: bytes
) -> bytes:
    """
    Descifra datos usando AES-256-GCM.

    Verifica automáticamente la autenticidad
    del contenido y los metadatos.
    """
    if len(clave_archivo) != 32:
        raise ValueError("La clave debe tener 32 bytes.")

    if len(nonce) != 12:
        raise ValueError("El nonce debe tener 12 bytes.")

    aesgcm = AESGCM(clave_archivo)

    return aesgcm.decrypt(
        nonce,
        datos_cifrados,
        aad
    )


def descifrar_con_contraseña(
    resultado_cifrado: dict,
    contraseña: str,
    aad: bytes
) -> bytes:
    """
    Recupera la clave protegida y descifra
    el contenido usando la contraseña.
    """
    clave_archivo = recuperar_clave(
        resultado_cifrado["clave_protegida"],
        contraseña
    )

    return descifrar_archivo(
        resultado_cifrado["datos_cifrados"],
        clave_archivo,
        resultado_cifrado["nonce"],
        aad
    )


def descifrar_contenedor(
    ruta: str,
    contraseña: str
) -> bytes:
    """
    Lee un archivo .vault, recupera la clave
    y descifra su contenido.
    """
    contenedor = leer_contenedor(ruta)

    aad = serializar_metadatos(
        contenedor["metadatos"]
    )

    return descifrar_con_contraseña(
        contenedor,
        contraseña,
        aad
    )
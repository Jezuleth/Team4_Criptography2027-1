
import os

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Generación de claves y valores aleatorios

def generar_clave_archivo() -> bytes:
    """
    Genera una clave AES-256 nueva para cada archivo.
    """
    return os.urandom(32)


def generar_nonce() -> bytes:
    """
    Genera un nonce aleatorio de 12 bytes para AES-GCM.
    """
    return os.urandom(12)


def generar_salt() -> bytes:
    """
    Genera un salt aleatorio de 16 bytes para scrypt.
    """
    return os.urandom(16)


# Derivación de clave desde una contraseña

def derivar_clave(contraseña: str, salt: bytes) -> bytes:
    """
    Deriva una clave de protección de 32 bytes usando scrypt.
    """
    if not contraseña:
        raise ValueError("La contraseña no puede estar vacía.")

    if len(salt) != 16:
        raise ValueError("El salt debe tener 16 bytes.")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )

    return kdf.derive(contraseña.encode("utf-8"))


# Protección de la clave individual del archivo

def proteger_clave(clave_archivo: bytes, contraseña: str) -> dict:
    """
    Protege una clave AES-256 usando la contraseña del propietario.

    Devuelve el salt, nonce y la clave cifrada.
    """
    if len(clave_archivo) != 32:
        raise ValueError("La clave del archivo debe tener 32 bytes.")

    salt = generar_salt()
    nonce = generar_nonce()

    # Derivar la clave de protección desde la contraseña
    clave_proteccion = derivar_clave(contraseña, salt)

    # Cifrar la clave del archivo con AES-256-GCM
    aesgcm = AESGCM(clave_proteccion)

    aad = b"D2-KEY-WRAP-v1"

    clave_cifrada = aesgcm.encrypt(
        nonce,
        clave_archivo,
        aad
    )

    return {
        "salt": salt,
        "nonce": nonce,
        "clave_cifrada": clave_cifrada
    }


def recuperar_clave(datos_protegidos: dict, contraseña: str) -> bytes:
    """
    Recupera la clave AES-256 del archivo usando
    la contraseña del propietario.

    Si la contraseña es incorrecta o los datos
    fueron modificados, AES-GCM rechaza el descifrado.
    """
    salt = datos_protegidos["salt"]
    nonce = datos_protegidos["nonce"]
    clave_cifrada = datos_protegidos["clave_cifrada"]

    if len(nonce) != 12:
        raise ValueError("El nonce debe tener 12 bytes.")

    # Obtener nuevamente la clave de protección
    clave_proteccion = derivar_clave(contraseña, salt)

    # Recuperar la clave original del archivo
    aesgcm = AESGCM(clave_proteccion)

    aad = b"D2-KEY-WRAP-v1"

    clave_archivo = aesgcm.decrypt(
        nonce,
        clave_cifrada,
        aad
    )

    return clave_archivo

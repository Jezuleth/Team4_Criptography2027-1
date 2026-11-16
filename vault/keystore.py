
"""D6: almacén cifrado de claves privadas."""

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class ErrorKeystore(Exception):
    """Error al almacenar o recuperar una clave."""


def _b64(datos):
    return base64.b64encode(datos).decode("ascii")


def _unb64(texto):
    return base64.b64decode(texto, validate=True)


def _derivar_clave(password, salt):
    if not isinstance(password, str) or not password:
        raise ErrorKeystore("Se requiere una contraseña.")

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def proteger_clave_privada(clave_privada, password, key_id):
    """Devuelve un keystore cifrado y serializable a JSON."""
    if not isinstance(clave_privada, bytes) or not clave_privada:
        raise ErrorKeystore("Clave privada inválida.")

    if not isinstance(key_id, str) or not key_id:
        raise ErrorKeystore("Identificador inválido.")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    clave_aes = _derivar_clave(password, salt)

    aad = f"D6-KEYSTORE-v1:{key_id}".encode("utf-8")
    cifrado = AESGCM(clave_aes).encrypt(
        nonce, clave_privada, aad
    )

    return {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": "scrypt",
        "key_id": key_id,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "ciphertext": _b64(cifrado),
    }


def recuperar_clave_privada(keystore, password):
    """Descifra la clave o rechaza una contraseña incorrecta."""
    try:
        if (
            type(keystore) is not dict
            or keystore["version"] != 1
            or keystore["algorithm"] != "AES-256-GCM"
            or keystore["kdf"] != "scrypt"
        ):
            raise ErrorKeystore("Formato no compatible.")

        key_id = keystore["key_id"]
        if not isinstance(key_id, str) or not key_id:
            raise ErrorKeystore("Identificador inválido.")

        salt = _unb64(keystore["salt"])
        nonce = _unb64(keystore["nonce"])
        cifrado = _unb64(keystore["ciphertext"])

        if len(salt) != 16 or len(nonce) != 12:
            raise ErrorKeystore("Parámetros inválidos.")

        clave_aes = _derivar_clave(password, salt)
        aad = f"D6-KEYSTORE-v1:{key_id}".encode("utf-8")

        return AESGCM(clave_aes).decrypt(
            nonce, cifrado, aad
        )

    except (InvalidTag, ValueError, KeyError, TypeError) as exc:
        raise ErrorKeystore(
            "Contraseña incorrecta o almacén alterado."
        ) from exc


def guardar_keystore(ruta, keystore):
    """Guarda el almacén con permisos restrictivos."""
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)

    datos = json.dumps(
        keystore, sort_keys=True, indent=2
    ).encode("utf-8")

    descriptor = os.open(
        ruta,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    with os.fdopen(descriptor, "wb") as archivo:
        archivo.write(datos)


def cargar_keystore(ruta):
    """Carga un almacén sin descifrar su contenido."""
    try:
        with open(ruta, "r", encoding="utf-8") as archivo:
            return json.load(archivo)
    except (OSError, ValueError) as exc:
        raise ErrorKeystore(
            "No se pudo cargar el almacén."
        ) from exc

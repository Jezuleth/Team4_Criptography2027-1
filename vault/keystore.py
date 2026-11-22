
"""D6: almacén cifrado de claves privadas."""

import base64
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LENGTH = 32
SCRYPT_N_ANTERIOR = 2**14


def _crear_aad_v2(metadatos):
    """Serializa de forma determinista los metadatos autenticados."""
    return b"D6-KEYSTORE-v2:" + json.dumps(
        metadatos,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class ErrorKeystore(Exception):
    """Error al almacenar o recuperar una clave."""


def validar_password(password):
    """Valida la contraseña al crear un nuevo keystore."""

    if not isinstance(password, str):
        raise ErrorKeystore("La contraseña debe ser texto.")

    if len(password) < 12:
        raise ErrorKeystore(
            "La contraseña debe tener al menos 12 caracteres."
        )

    if len(password) > 1024:
        raise ErrorKeystore("Contraseña demasiado larga.")

    if password.strip() != password:
        raise ErrorKeystore(
            "La contraseña no debe comenzar ni terminar con espacios."
        )

    if password.lower() in {
        "password1234",
        "contraseña123",
        "123456789012",
    }:
        raise ErrorKeystore("La contraseña es demasiado común.")


def _b64(datos):
    return base64.b64encode(datos).decode("ascii")


def _unb64(texto):
    return base64.b64decode(texto, validate=True)


def _derivar_clave(password, salt, n=SCRYPT_N):
    if not isinstance(password, str) or not password:
        raise ErrorKeystore("Se requiere una contraseña.")

    kdf = Scrypt(
        salt=salt,
        length=SCRYPT_LENGTH,
        n=n,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))


def proteger_clave_privada(clave_privada, password, key_id):
    """Crea un keystore v2 cifrado y autenticado."""
    validar_password(password)

    if not isinstance(clave_privada, bytes) or not clave_privada:
        raise ErrorKeystore("Clave privada inválida.")

    if not isinstance(key_id, str) or not key_id:
        raise ErrorKeystore("Identificador inválido.")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    clave_aes = _derivar_clave(password, salt)

    metadatos = {
        "version": 2,
        "algorithm": "AES-256-GCM",
        "kdf": "scrypt",
        "kdf_params": {
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "length": SCRYPT_LENGTH,
        },
        "key_id": key_id,
        "salt": _b64(salt),
        "nonce": _b64(nonce),
    }

    aad = _crear_aad_v2(metadatos)
    cifrado = AESGCM(clave_aes).encrypt(
        nonce, clave_privada, aad
    )

    return {
        **metadatos,
        "ciphertext": _b64(cifrado),
    }


def recuperar_clave_privada(keystore, password):
    """Recupera claves de keystores v1 y v2."""
    try:
        if type(keystore) is not dict:
            raise ErrorKeystore("Formato no compatible.")

        version = keystore["version"]

        if type(version) is not int or version not in (1, 2):
            raise ErrorKeystore("Formato no compatible.")

        if (
            keystore["algorithm"] != "AES-256-GCM"
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

        if version == 1:
            aad = f"D6-KEYSTORE-v1:{key_id}".encode("utf-8")
            n = SCRYPT_N_ANTERIOR

        else:
            parametros = keystore["kdf_params"]

            if (
                type(parametros) is not dict
                or set(parametros) != {"n", "r", "p", "length"}
                or type(parametros["n"]) is not int
                or parametros["n"] not in (
                    SCRYPT_N_ANTERIOR,
                    SCRYPT_N,
                )
                or type(parametros["r"]) is not int
                or parametros["r"] != SCRYPT_R
                or type(parametros["p"]) is not int
                or parametros["p"] != SCRYPT_P
                or type(parametros["length"]) is not int
                or parametros["length"] != SCRYPT_LENGTH
            ):
                raise ErrorKeystore(
                    "Parámetros Scrypt no compatibles o alterados."
                )

            metadatos = {
                campo: valor
                for campo, valor in keystore.items()
                if campo != "ciphertext"
            }

            aad = _crear_aad_v2(metadatos)
            n = parametros["n"]

        clave_aes = _derivar_clave(password, salt, n=n)

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


def eliminar_keystore(ruta):
    """Retira un almacén del repositorio de claves. True si existía.

    Sobrescribe el contenido con bytes aleatorios antes de borrarlo (mejor
    esfuerzo: en SSD, sistemas copy-on-write o con journaling no hay garantía
    de borrado físico; el cifrado del almacén sigue siendo la protección real).
    """
    ruta = Path(ruta)
    try:
        if not ruta.is_symlink():
            tamano = ruta.stat().st_size
            with open(ruta, "r+b") as archivo:
                archivo.write(os.urandom(tamano))
                archivo.flush()
                os.fsync(archivo.fileno())
        ruta.unlink()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ErrorKeystore(
            "No se pudo eliminar el almacén de claves."
        ) from exc
    return True

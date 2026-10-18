
import json
from datetime import datetime, timezone

VERSION = 1
ALGORITMO = "AES-256-GCM"


def crear_metadatos(nombre_archivo: str) -> dict:
    if not nombre_archivo:
        raise ValueError("El nombre del archivo es obligatorio.")

    return {
        "nombre_archivo": nombre_archivo,
        "fecha": datetime.now(timezone.utc).isoformat(),
        "version": VERSION,
        "algoritmo": ALGORITMO,
    }


def serializar_metadatos(metadatos: dict) -> bytes:
    return json.dumps(
        metadatos,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


import base64


def _a_base64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def crear_contenedor(metadatos: dict, resultado_cifrado: dict) -> dict:
    clave_protegida = resultado_cifrado["clave_protegida"]

    return {
        "header": metadatos,
        "nonce": _a_base64(resultado_cifrado["nonce"]),
        "ciphertext": _a_base64(resultado_cifrado["datos_cifrados"]),
        "clave_protegida": {
            "salt": _a_base64(clave_protegida["salt"]),
            "nonce": _a_base64(clave_protegida["nonce"]),
            "clave_cifrada": _a_base64(clave_protegida["clave_cifrada"]),
        },
    }

from pathlib import Path
import binascii


def _desde_base64(texto: str) -> bytes:
    try:
        return base64.b64decode(texto, validate=True)
    except (ValueError, binascii.Error, TypeError) as error:
        raise ValueError("Datos Base64 inválidos.") from error


def guardar_contenedor(contenedor: dict, ruta: str) -> None:
    Path(ruta).write_text(
        json.dumps(
            contenedor,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ),
        encoding="utf-8",
    )


def leer_contenedor(ruta: str) -> dict:
    contenedor = json.loads(
        Path(ruta).read_text(encoding="utf-8")
    )

    metadatos = contenedor["header"]

    if metadatos["version"] != VERSION:
        raise ValueError("Versión de contenedor no compatible.")

    if metadatos["algoritmo"] != ALGORITMO:
        raise ValueError("Algoritmo no compatible.")

    nonce = _desde_base64(contenedor["nonce"])
    datos_cifrados = _desde_base64(contenedor["ciphertext"])

    clave_protegida = contenedor["clave_protegida"]

    salt = _desde_base64(clave_protegida["salt"])
    nonce_clave = _desde_base64(clave_protegida["nonce"])
    clave_cifrada = _desde_base64(clave_protegida["clave_cifrada"])

    if len(nonce) != 12 or len(nonce_clave) != 12:
        raise ValueError("Longitud de nonce inválida.")

    if len(salt) != 16:
        raise ValueError("Longitud de salt inválida.")

    if len(datos_cifrados) < 16:
        raise ValueError("Contenido cifrado inválido.")

    if len(clave_cifrada) != 48:
        raise ValueError("Clave protegida inválida.")

    return {
        "metadatos": metadatos,
        "nonce": nonce,
        "datos_cifrados": datos_cifrados,
        "clave_protegida": {
            "salt": salt,
            "nonce": nonce_clave,
            "clave_cifrada": clave_cifrada,
        },
    }

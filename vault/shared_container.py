"""
Contenedor compartido (formato v2) del D3.

Estructura del archivo .vault:

{
  "header": {
    "nombre_archivo", "fecha", "version": 2,
    "algoritmo": "AES-256-GCM",
    "algoritmo_envoltura": "RSA-OAEP-SHA256",
    "algoritmo_huella": "SHA256-SPKI-DER",
    "id_archivo": <16 bytes aleatorios, base64>
  },
  "recipients": [
    {"id": "alice", "key_id": <huella SHA-256 hex>, "encrypted_key": <base64>},
    ...
  ],
  "nonce": <12 bytes, base64>,
  "ciphertext": <base64>,
  "tag": <16 bytes, base64>
}

El AAD de AES-GCM cubre header + recipients completos (ids, key_ids,
claves envueltas e identificadores de algoritmo), de modo que añadir,
quitar, reordenar o modificar destinatarios invalida la autenticación.
"""

import base64
import binascii
import json
import os
import re
import unicodedata
from datetime import datetime, timezone
from pathlib import Path

from vault.public_key import ALGORITMO_ENVOLTURA, ALGORITMO_HUELLA

VERSION_COMPARTIDO = 2
ALGORITMO_CONTENIDO = "AES-256-GCM"

TAMANO_NONCE = 12
TAMANO_TAG = 16
TAMANO_ID_ARCHIVO = 16
TAMANO_MINIMO_CLAVE_ENVUELTA = 256  # RSA-2048 -> 256 bytes
MAX_DESTINATARIOS = 256
MAX_LONGITUD_ID = 128

_PREFIJO_AAD = b"D3-VAULT-AAD-v2\n"
_CATEGORIAS_PROHIBIDAS = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
_REGEX_HUELLA = re.compile(r"[0-9a-f]{64}")

_CAMPOS_CONTENEDOR = {"header", "recipients", "nonce", "ciphertext", "tag"}
_CAMPOS_HEADER = {
    "nombre_archivo",
    "fecha",
    "version",
    "algoritmo",
    "algoritmo_envoltura",
    "algoritmo_huella",
    "id_archivo",
}
_CAMPOS_DESTINATARIO = {"id", "key_id", "encrypted_key"}


class ContenedorInvalido(ValueError):
    """El contenedor compartido está mal formado o usa algo no soportado."""


# Base64 estricto

def a_base64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def desde_base64(texto) -> bytes:
    if not isinstance(texto, str):
        raise ContenedorInvalido("Datos Base64 inválidos.")

    try:
        datos = base64.b64decode(texto, validate=True)
    except (ValueError, binascii.Error) as error:
        raise ContenedorInvalido("Datos Base64 inválidos.") from error

    # Solo se acepta la codificación canónica: evita que dos textos
    # distintos representen los mismos bytes (maleabilidad del archivo).
    if a_base64(datos) != texto:
        raise ContenedorInvalido("Base64 no canónico.")

    return datos


# Construcción

def crear_encabezado(nombre_archivo: str) -> dict:
    if not nombre_archivo:
        raise ValueError("El nombre del archivo es obligatorio.")

    return {
        "nombre_archivo": nombre_archivo,
        "fecha": datetime.now(timezone.utc).isoformat(),
        "version": VERSION_COMPARTIDO,
        "algoritmo": ALGORITMO_CONTENIDO,
        "algoritmo_envoltura": ALGORITMO_ENVOLTURA,
        "algoritmo_huella": ALGORITMO_HUELLA,
        "id_archivo": a_base64(os.urandom(TAMANO_ID_ARCHIVO)),
    }


def _validar_texto_utf8(texto: str) -> None:
    """Rechaza cadenas que no se pueden codificar (p. ej. sustitutos sueltos)."""
    try:
        texto.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError("Texto con caracteres Unicode inválidos.") from error


def validar_id_destinatario(id_destinatario) -> str:
    """
    Identificador de usuario: texto NFC, sin espacios en los extremos y
    sin caracteres de control, de formato (p. ej. U+200B, U+202E),
    separadores de línea/párrafo ni sustitutos. Esto evita ids
    visualmente idénticos pero distintos.
    """
    if not isinstance(id_destinatario, str) or not id_destinatario.strip():
        raise ValueError("El identificador de usuario no puede estar vacío.")

    if len(id_destinatario) > MAX_LONGITUD_ID:
        raise ValueError("El identificador de usuario es demasiado largo.")

    _validar_texto_utf8(id_destinatario)

    if id_destinatario != id_destinatario.strip():
        raise ValueError("El identificador tiene espacios al inicio o al final.")

    if unicodedata.normalize("NFC", id_destinatario) != id_destinatario:
        raise ValueError("El identificador debe estar normalizado (NFC).")

    for caracter in id_destinatario:
        if unicodedata.category(caracter) in _CATEGORIAS_PROHIBIDAS:
            raise ValueError("El identificador contiene caracteres no permitidos.")

    return id_destinatario


def clave_unicidad_id(id_destinatario: str) -> str:
    """Dos ids que difieren solo en mayúsculas/minúsculas cuentan como iguales."""
    return id_destinatario.casefold()


# AAD

def construir_aad(encabezado: dict, destinatarios: list) -> bytes:
    """
    Serialización canónica y determinista de todo lo que debe quedar
    autenticado: encabezado completo y lista de destinatarios completa
    (con su orden).
    """
    cuerpo = json.dumps(
        {"header": encabezado, "recipients": destinatarios},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    return _PREFIJO_AAD + cuerpo


# Validación estructural

def validar_contenedor(contenedor) -> None:
    """
    Validación estricta del formato (campos exactos, longitudes, algoritmos,
    unicidad de ids y key_ids). No hace criptografía: solo evita procesar
    contenedores malformados o con campos no autenticados.
    """
    if not isinstance(contenedor, dict):
        raise ContenedorInvalido("El contenedor debe ser un objeto JSON.")

    if set(contenedor) != _CAMPOS_CONTENEDOR:
        raise ContenedorInvalido("Campos del contenedor inesperados.")

    encabezado = contenedor["header"]

    if not isinstance(encabezado, dict) or set(encabezado) != _CAMPOS_HEADER:
        raise ContenedorInvalido("Encabezado inválido.")

    version = encabezado["version"]

    if type(version) is not int or version != VERSION_COMPARTIDO:
        raise ContenedorInvalido("Versión de contenedor no compatible.")

    if encabezado["algoritmo"] != ALGORITMO_CONTENIDO:
        raise ContenedorInvalido("Algoritmo de contenido no compatible.")

    if encabezado["algoritmo_envoltura"] != ALGORITMO_ENVOLTURA:
        raise ContenedorInvalido("Algoritmo de envoltura no compatible.")

    if encabezado["algoritmo_huella"] != ALGORITMO_HUELLA:
        raise ContenedorInvalido("Algoritmo de huella no compatible.")

    for campo in ("nombre_archivo", "fecha"):
        valor = encabezado[campo]

        if not isinstance(valor, str) or not valor:
            raise ContenedorInvalido(f"Campo de encabezado inválido: {campo}.")

        try:
            _validar_texto_utf8(valor)
        except ValueError as error:
            raise ContenedorInvalido(str(error)) from error

    if len(desde_base64(encabezado["id_archivo"])) != TAMANO_ID_ARCHIVO:
        raise ContenedorInvalido("Identificador de archivo inválido.")

    destinatarios = contenedor["recipients"]

    if not isinstance(destinatarios, list) or not destinatarios:
        raise ContenedorInvalido("El contenedor no tiene destinatarios.")

    if len(destinatarios) > MAX_DESTINATARIOS:
        raise ContenedorInvalido("Demasiados destinatarios.")

    ids_vistos = set()
    huellas_vistas = set()

    for entrada in destinatarios:
        if not isinstance(entrada, dict) or set(entrada) != _CAMPOS_DESTINATARIO:
            raise ContenedorInvalido("Entrada de destinatario inválida.")

        try:
            id_destinatario = validar_id_destinatario(entrada["id"])
        except ValueError as error:
            raise ContenedorInvalido(str(error)) from error

        huella = entrada["key_id"]

        if not isinstance(huella, str) or not _REGEX_HUELLA.fullmatch(huella):
            raise ContenedorInvalido("Identificador de clave inválido.")

        clave_envuelta = desde_base64(entrada["encrypted_key"])

        if len(clave_envuelta) < TAMANO_MINIMO_CLAVE_ENVUELTA:
            raise ContenedorInvalido("Clave envuelta inválida.")

        unico = clave_unicidad_id(id_destinatario)

        if unico in ids_vistos or huella in huellas_vistas:
            raise ContenedorInvalido("Destinatarios duplicados.")

        ids_vistos.add(unico)
        huellas_vistas.add(huella)

    if len(desde_base64(contenedor["nonce"])) != TAMANO_NONCE:
        raise ContenedorInvalido("Longitud de nonce inválida.")

    if len(desde_base64(contenedor["tag"])) != TAMANO_TAG:
        raise ContenedorInvalido("Longitud de tag inválida.")

    desde_base64(contenedor["ciphertext"])


# Persistencia

def _rechazar_claves_duplicadas(pares):
    objeto = {}

    for clave, valor in pares:
        if clave in objeto:
            raise ContenedorInvalido(f"Campo JSON duplicado: {clave}")
        objeto[clave] = valor

    return objeto


def guardar_contenedor_compartido(contenedor: dict, ruta) -> None:
    """Valida y guarda el contenedor; la escritura es atómica."""
    validar_contenedor(contenedor)

    destino = Path(ruta)
    temporal = destino.with_name(destino.name + ".tmp")

    temporal.write_text(
        json.dumps(
            contenedor,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        ),
        encoding="utf-8",
    )

    os.replace(temporal, destino)


def leer_contenedor_compartido(ruta) -> dict:
    """
    Lee y valida un contenedor v2. Rechaza JSON con campos duplicados
    (evita ambigüedades entre parsers). Cualquier archivo ilegible o mal
    formado se reporta como ContenedorInvalido.
    """
    try:
        contenedor = json.loads(
            Path(ruta).read_text(encoding="utf-8"),
            object_pairs_hook=_rechazar_claves_duplicadas,
        )
    except (ValueError, RecursionError) as error:
        # JSONDecodeError y UnicodeDecodeError son subclases de ValueError
        if isinstance(error, ContenedorInvalido):
            raise

        raise ContenedorInvalido("El archivo no es un contenedor JSON válido.") from error

    validar_contenedor(contenedor)
    return contenedor

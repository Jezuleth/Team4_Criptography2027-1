"""
Gestión de claves públicas para el cifrado híbrido (D3).

Este módulo SOLO maneja claves asimétricas pequeñas:
  - generación de pares RSA,
  - huella (fingerprint) que identifica cada clave pública,
  - serialización PEM,
  - envoltura (wrap) / desenvoltura (unwrap) de la clave simétrica del
    archivo con RSA-OAEP.

Nunca se cifra un archivo con una clave pública. Lo único que entra a
RSA-OAEP es la clave de archivo de 32 bytes.
"""

import hashlib
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Identificadores de algoritmo (quedan autenticados en el AAD del contenedor)
ALGORITMO_ENVOLTURA = "RSA-OAEP-SHA256"
ALGORITMO_HUELLA = "SHA256-SPKI-DER"

TAMANO_MINIMO_RSA = 2048
TAMANO_RSA_POR_DEFECTO = 3072
TAMANO_CLAVE_ARCHIVO = 32

_ETIQUETA_BASE = "D3-FILEKEY-WRAP-v1"


class ErrorDeAcceso(Exception):
    """Base de los errores por falta de acceso a un contenedor compartido."""


class DestinatarioNoAutorizado(ErrorDeAcceso):
    """La clave privada presentada no corresponde a ningún destinatario."""


# Generación y validación de claves

def generar_par_claves(bits: int = TAMANO_RSA_POR_DEFECTO) -> rsa.RSAPrivateKey:
    """
    Genera un par de claves RSA. Devuelve la clave privada
    (la pública se obtiene con .public_key()).
    """
    if bits < TAMANO_MINIMO_RSA:
        raise ValueError(
            f"El tamaño mínimo de clave RSA es {TAMANO_MINIMO_RSA} bits."
        )

    return rsa.generate_private_key(public_exponent=65537, key_size=bits)


def validar_clave_publica(clave_publica) -> rsa.RSAPublicKey:
    """
    Verifica que la clave sea RSA y de tamaño aceptable.
    Rechaza otros tipos de clave y claves débiles.
    """
    if not isinstance(clave_publica, rsa.RSAPublicKey):
        raise ValueError("La clave pública debe ser RSA.")

    if clave_publica.key_size < TAMANO_MINIMO_RSA:
        raise ValueError(
            f"Clave RSA demasiado pequeña (mínimo {TAMANO_MINIMO_RSA} bits)."
        )

    if clave_publica.public_numbers().e != 65537:
        raise ValueError("Exponente público RSA no soportado (se requiere 65537).")

    return clave_publica


# Identificación de claves (key ID)

def huella_clave_publica(clave_publica) -> str:
    """
    Huella determinista de una clave pública: SHA-256 (hex, 64 caracteres)
    de su codificación DER SubjectPublicKeyInfo.

    La misma clave pública produce siempre la misma huella, y dos claves
    distintas producen huellas distintas (resistencia a colisiones de SHA-256).
    Se usa la huella completa, sin truncar.
    """
    validar_clave_publica(clave_publica)

    der = clave_publica.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return hashlib.sha256(der).hexdigest()


def verificar_huella(clave_publica, huella_esperada: str) -> None:
    """
    Comprueba una clave pública contra una huella obtenida por un canal
    de confianza (en persona, directorio firmado, etc.).

    Lanza ValueError si no coincide: así se detecta una clave pública
    sustituida antes de compartir un archivo con ella.
    """
    if huella_clave_publica(clave_publica) != huella_esperada.strip().lower():
        raise ValueError(
            "La huella de la clave pública no coincide con la esperada."
        )


# Serialización PEM

def serializar_clave_publica(clave_publica) -> bytes:
    validar_clave_publica(clave_publica)

    return clave_publica.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def cargar_clave_publica(pem: bytes) -> rsa.RSAPublicKey:
    clave = serialization.load_pem_public_key(pem)
    return validar_clave_publica(clave)


def serializar_clave_privada(clave_privada, contraseña: str) -> bytes:
    """Exporta la clave privada en PEM cifrado con una contraseña."""
    if not contraseña:
        raise ValueError("La contraseña no puede estar vacía.")

    return clave_privada.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            contraseña.encode("utf-8")
        ),
    )


def cargar_clave_privada(pem: bytes, contraseña: str) -> rsa.RSAPrivateKey:
    try:
        clave = serialization.load_pem_private_key(
            pem,
            password=contraseña.encode("utf-8"),
        )
    except TypeError as error:
        # PEM sin cifrar cargado con contraseña
        raise ValueError("La clave privada no está cifrada con contraseña.") from error

    if not isinstance(clave, rsa.RSAPrivateKey):
        raise ValueError("La clave privada debe ser RSA.")

    validar_clave_publica(clave.public_key())
    return clave


# Envoltura de la clave de archivo con RSA-OAEP

def crear_etiqueta_envoltura(
    id_archivo: str,
    id_clave: str,
    id_destinatario: str,
) -> bytes:
    """
    Etiqueta OAEP (label) que ata la clave envuelta a su contexto:
    este archivo, esta clave pública y este identificador de usuario.

    OAEP autentica la etiqueta al desenvolver, así que una entrada copiada
    a otro contenedor, o reasignada a otra identidad, falla al descifrar.
    """
    return json.dumps(
        {
            "contexto": _ETIQUETA_BASE,
            "id_archivo": id_archivo,
            "id_clave": id_clave,
            "id_destinatario": id_destinatario,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _padding_oaep(etiqueta: bytes) -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=etiqueta,
    )


def envolver_clave(clave_archivo: bytes, clave_publica, etiqueta: bytes) -> bytes:
    """
    Cifra la clave de archivo (32 bytes) con la clave pública del
    destinatario usando RSA-OAEP (SHA-256).

    OAEP es probabilístico: envolver la misma clave dos veces produce
    resultados distintos.
    """
    if len(clave_archivo) != TAMANO_CLAVE_ARCHIVO:
        raise ValueError(
            "Solo se pueden envolver claves simétricas de 32 bytes."
        )

    validar_clave_publica(clave_publica)

    return clave_publica.encrypt(clave_archivo, _padding_oaep(etiqueta))


def desenvolver_clave(
    clave_envuelta: bytes,
    clave_privada,
    etiqueta: bytes,
) -> bytes:
    """
    Recupera la clave de archivo con la clave privada del destinatario.

    Cualquier fallo (clave privada equivocada, etiqueta distinta, datos
    alterados) se reporta con un único error genérico, sin dar detalles
    que sirvan como oráculo.
    """
    try:
        clave_archivo = clave_privada.decrypt(
            clave_envuelta,
            _padding_oaep(etiqueta),
        )
    except ValueError as error:
        raise ErrorDeAcceso(
            "No se pudo recuperar la clave del archivo."
        ) from error

    if len(clave_archivo) != TAMANO_CLAVE_ARCHIVO:
        raise ErrorDeAcceso("No se pudo recuperar la clave del archivo.")

    return clave_archivo

import hashlib
import json

import hmac

from ecies import encrypt as ecies_encrypt, decrypt as ecies_decrypt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

# Identificadores de algoritmo (quedan autenticados en el AAD del contenedor)
ALGORITMO_ENVOLTURA = "ECIES-SECP256K1"
ALGORITMO_HUELLA = "SHA256-SPKI-DER"

TAMANO_CLAVE_ARCHIVO = 32
CURVA_ECIES = ec.SECP256K1()

_ETIQUETA_BASE = "D3-FILEKEY-ECIES-v1"

class ErrorDeAcceso(Exception):
    """Base de los errores por falta de acceso a un contenedor compartido."""


class DestinatarioNoAutorizado(ErrorDeAcceso):
    """La clave privada presentada no corresponde a ningún destinatario."""


# Generación y validación de claves

def generar_par_claves() -> ec.EllipticCurvePrivateKey:
    """
    Genera un par de claves de curva elíptica secp256k1.
    La clave pública se obtiene con .public_key().
    """
    return ec.generate_private_key(CURVA_ECIES)


def validar_clave_publica(clave_publica) -> ec.EllipticCurvePublicKey:
    """
    Verifica que la clave pública sea EC y utilice secp256k1.
    """
    if not isinstance(clave_publica, ec.EllipticCurvePublicKey):
        raise ValueError("La clave pública debe ser de curva elíptica.")

    if not isinstance(clave_publica.curve, ec.SECP256K1):
        raise ValueError("Solo se admite la curva secp256k1.")

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


def cargar_clave_publica(pem: bytes) -> ec.EllipticCurvePublicKey:
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


def cargar_clave_privada(pem: bytes, contraseña: str) -> ec.EllipticCurvePrivateKey:
    try:
        clave = serialization.load_pem_private_key(
            pem,
            password=contraseña.encode("utf-8"),
        )
    except TypeError as error:
        raise ValueError(
            "La clave privada no está cifrada con contraseña."
        ) from error

    if not isinstance(clave, ec.EllipticCurvePrivateKey):
        raise ValueError("La clave privada debe ser de curva elíptica.")

    validar_clave_publica(clave.public_key())
    return clave


# Envoltura de la clave de archivo con ECIES (secp256k1)

def crear_etiqueta_envoltura(
    id_archivo: str,
    id_clave: str,
    id_destinatario: str,
) -> bytes:
    """
    Construye una etiqueta de contexto para proteger la clave AES
    mediante ECIES (secp256k1).

    La etiqueta identifica el archivo, la huella de la clave pública
    y el destinatario.

    Su hash SHA-256 se incluye dentro del mensaje cifrado con ECIES
    y se verifica al descifrar.

    Esto impide reutilizar una clave envuelta en otro archivo
    o asociarla a un destinatario diferente sin detectar el cambio.
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


def envolver_clave(clave_archivo: bytes, clave_publica, etiqueta: bytes) -> bytes:
    """
    Protege la clave AES-256 mediante ECIES con secp256k1.

    Incluye un hash del contexto para vincular la clave cifrada
    al archivo y al destinatario correspondientes.
    """
    if len(clave_archivo) != TAMANO_CLAVE_ARCHIVO:
        raise ValueError(
            "Solo se pueden envolver claves simétricas de 32 bytes."
        )

    validar_clave_publica(clave_publica)

    clave_publica_hex = clave_publica.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    ).hex()

    contexto = hashlib.sha256(etiqueta).digest()
    mensaje = contexto + clave_archivo

    return ecies_encrypt(clave_publica_hex, mensaje)


def desenvolver_clave(
    clave_envuelta: bytes,
    clave_privada,
    etiqueta: bytes,
) -> bytes:
    """
    Recupera la clave AES utilizando ECIES.

    Rechaza claves incorrectas, datos alterados o contextos
    que no coincidan con el archivo y destinatario originales.
    """
    try:
        if not isinstance(clave_privada, ec.EllipticCurvePrivateKey):
            raise ValueError("Clave privada inválida.")

        validar_clave_publica(clave_privada.public_key())

        clave_privada_hex = clave_privada.private_numbers().private_value.to_bytes(
            32, "big"
        ).hex()

        mensaje = ecies_decrypt(clave_privada_hex, clave_envuelta)

        contexto_esperado = hashlib.sha256(etiqueta).digest()

        if (
            len(mensaje) != 64
            or not hmac.compare_digest(mensaje[:32], contexto_esperado)
        ):
            raise ValueError("Contexto de cifrado inválido.")

        return mensaje[32:]

    except (ValueError, TypeError) as error:
        raise ErrorDeAcceso(
            "No se pudo recuperar la clave del archivo."
        ) from error
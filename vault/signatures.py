"""D5 - Firmas digitales (Ed25519) para el Secure Digital Document Vault.

Flujo: Hash -> Firma -> Verificación.

Qué se firma
------------
Se firma el SHA-256 de:

    CONTEXTO_FIRMA || JSON canónico del contenedor completo SIN el campo "signature"

Es decir: header, recipients, nonce, ciphertext, tag, signer_id y
signature_algorithm. Esto es un superconjunto del AAD de D3, de modo que
cualquier cambio en metadatos, lista de destinatarios, texto cifrado, tag,
identidad del firmante o algoritmo invalida la firma.

Identificación del firmante
---------------------------
signer_id = SHA-256 (hex) del DER SubjectPublicKeyInfo de la clave pública
Ed25519 (misma convención que el key_id de D3).

Codificación
------------
Firma Ed25519 de 64 bytes (RFC 8032) en Base64 estándar (RFC 4648), estricto.
Claves privadas: PKCS#8 PEM cifrado con contraseña. Públicas: SPKI PEM.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

ALGORITMO_FIRMA = "ED25519-SHA256"

# Separación de dominio: esta firma no puede reutilizarse en otro protocolo.
CONTEXTO_FIRMA = b"SECURE-DIGITAL-DOCUMENT-VAULT/D5/SIGNATURE/v1\x00"

CAMPOS_FIRMA = ("signer_id", "signature_algorithm", "signature")

_LONGITUD_FIRMA = 64
_MENSAJE = "Firma inválida: el contenedor no es auténtico o fue modificado."


class ErrorFirma(Exception):
    """Único tipo de error de D5. El mensaje es genérico a propósito
    (no revela qué comprobación falló)."""


# --------------------------------------------------------------------------
# Claves
# --------------------------------------------------------------------------
def generar_par_claves_firma() -> Ed25519PrivateKey:
    """Genera una clave de firma Ed25519.

    Debe ser DISTINTA de la clave ECIES (secp256k1) de D3: una clave, un uso.
    """
    return Ed25519PrivateKey.generate()


def huella_clave_firma(clave_publica: Ed25519PublicKey) -> str:
    """SHA-256 (hex) del DER SubjectPublicKeyInfo. Se usa como signer_id."""
    if not isinstance(clave_publica, Ed25519PublicKey):
        raise ErrorFirma("La clave pública de firma debe ser Ed25519.")
    der = clave_publica.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def exportar_clave_privada_firma(clave: Ed25519PrivateKey, password: bytes) -> bytes:
    if not isinstance(clave, Ed25519PrivateKey):
        raise ErrorFirma("La clave privada de firma debe ser Ed25519.")
    if not password:
        raise ErrorFirma("Se requiere una contraseña para proteger la clave.")
    return clave.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )


def importar_clave_privada_firma(pem: bytes, password: bytes) -> Ed25519PrivateKey:
    try:
        clave = serialization.load_pem_private_key(pem, password=password)
    except (ValueError, TypeError):
        raise ErrorFirma("No se pudo cargar la clave privada de firma.") from None
    if not isinstance(clave, Ed25519PrivateKey):
        raise ErrorFirma("La clave privada de firma debe ser Ed25519.")
    return clave


def exportar_clave_publica_firma(clave: Ed25519PublicKey) -> bytes:
    if not isinstance(clave, Ed25519PublicKey):
        raise ErrorFirma("La clave pública de firma debe ser Ed25519.")
    return clave.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def importar_clave_publica_firma(pem: bytes) -> Ed25519PublicKey:
    try:
        clave = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError):
        raise ErrorFirma("No se pudo cargar la clave pública de firma.") from None
    if not isinstance(clave, Ed25519PublicKey):
        raise ErrorFirma("La clave pública de firma debe ser Ed25519.")
    return clave


# --------------------------------------------------------------------------
# Qué se firma
# --------------------------------------------------------------------------
def bytes_a_firmar(contenedor: Mapping[str, Any]) -> bytes:
    """Mensaje canónico: contexto || JSON canónico (sin 'signature')."""
    sin_firma = {k: v for k, v in contenedor.items() if k != "signature"}
    canonico = json.dumps(
        sin_firma,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")
    return CONTEXTO_FIRMA + canonico


def digest_a_firmar(contenedor: Mapping[str, Any]) -> bytes:
    """Paso 'Hash': SHA-256 del mensaje canónico (32 bytes)."""
    return hashlib.sha256(bytes_a_firmar(contenedor)).digest()


# --------------------------------------------------------------------------
# Firmar / verificar
# --------------------------------------------------------------------------
def firmar_contenedor(
    contenedor: Mapping[str, Any], clave_privada: Ed25519PrivateKey
) -> dict[str, Any]:
    """Devuelve una COPIA del contenedor con signer_id, signature_algorithm
    y signature. No modifica el original."""
    if not isinstance(clave_privada, Ed25519PrivateKey):
        raise ErrorFirma("La clave privada de firma debe ser Ed25519.")
    if any(campo in contenedor for campo in CAMPOS_FIRMA):
        raise ErrorFirma("El contenedor ya contiene campos de firma.")

    firmado = dict(contenedor)
    firmado["signer_id"] = huella_clave_firma(clave_privada.public_key())
    firmado["signature_algorithm"] = ALGORITMO_FIRMA
    firma = clave_privada.sign(digest_a_firmar(firmado))  # Hash -> Sign
    firmado["signature"] = base64.b64encode(firma).decode("ascii")
    return firmado


def _decodificar_firma(valor: Any) -> bytes:
    if not isinstance(valor, str):
        raise ErrorFirma(_MENSAJE)
    try:
        firma = base64.b64decode(valor.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ErrorFirma(_MENSAJE) from None
    # Base64 canónico: sin variantes que decodifican a los mismos bytes.
    if len(firma) != _LONGITUD_FIRMA or base64.b64encode(firma).decode() != valor:
        raise ErrorFirma(_MENSAJE)
    return firma


def verificar_contenedor(
    contenedor: Mapping[str, Any], clave_publica: Ed25519PublicKey
) -> None:
    """Verifica la firma. No devuelve nada: o pasa, o lanza ErrorFirma.

    `clave_publica` debe provenir de un canal confiable (ver huella).
    """
    if not isinstance(contenedor, Mapping):
        raise ErrorFirma(_MENSAJE)
    if not isinstance(clave_publica, Ed25519PublicKey):
        raise ErrorFirma(_MENSAJE)

    for campo in CAMPOS_FIRMA:  # firma eliminada -> rechazo
        if campo not in contenedor:
            raise ErrorFirma(_MENSAJE)

    signer_id = contenedor["signer_id"]
    if not isinstance(signer_id, str):
        raise ErrorFirma(_MENSAJE)
    if contenedor["signature_algorithm"] != ALGORITMO_FIRMA:  # sin downgrade
        raise ErrorFirma(_MENSAJE)
    # La clave esperada debe ser la que el contenedor declara como firmante.
    if not hmac.compare_digest(
        signer_id.encode("ascii", "replace"),
        huella_clave_firma(clave_publica).encode("ascii"),
    ):
        raise ErrorFirma(_MENSAJE)

    firma = _decodificar_firma(contenedor["signature"])
    try:
        clave_publica.verify(firma, digest_a_firmar(contenedor))
    except (InvalidSignature, ValueError, TypeError):
        raise ErrorFirma(_MENSAJE) from None

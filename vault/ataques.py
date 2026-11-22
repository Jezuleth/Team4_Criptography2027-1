"""Simulaciones de ataque sobre un contenedor firmado (solo para demostración
y pruebas). Cada función devuelve una COPIA modificada; el original no cambia.

La usan app.py (Laboratorio), demo_final.py y las pruebas, para que los tres
ataquen exactamente igual.
"""

from __future__ import annotations

import base64

from vault.signatures import CAMPOS_FIRMA, firmar_contenedor, generar_par_claves_firma


def quitar_firma(contenedor: dict) -> dict:
    """Archivo sin firma: elimina signer_id, signature_algorithm y signature."""
    return {k: v for k, v in contenedor.items() if k not in CAMPOS_FIRMA}


def alterar_cifrado(contenedor: dict) -> dict:
    """Invierte un bit del texto cifrado (o del tag si el archivo está vacío)."""
    copia = dict(contenedor)
    campo = "ciphertext" if base64.b64decode(copia["ciphertext"]) else "tag"
    datos = bytearray(base64.b64decode(copia[campo]))
    datos[0] ^= 0x01
    copia[campo] = base64.b64encode(bytes(datos)).decode("ascii")
    return copia


def truncar_firma(contenedor: dict, longitud: int = 63) -> dict:
    """Firma incompleta: menos de los 64 bytes de Ed25519."""
    firma = base64.b64decode(contenedor["signature"])[:longitud]
    return {**contenedor, "signature": base64.b64encode(firma).decode("ascii")}


def truncar_huella_firmante(contenedor: dict, caracteres: int = 32) -> dict:
    """Llave con hash incompleto: signer_id recortado."""
    return {**contenedor, "signer_id": contenedor["signer_id"][:caracteres]}


def suplantar_remitente(contenedor: dict, clave_atacante=None) -> dict:
    """El atacante vuelve a firmar el mismo contenido con SU llave."""
    return firmar_contenedor(
        quitar_firma(contenedor), clave_atacante or generar_par_claves_firma()
    )


# Catálogo: (clave, título, explicación, función)
CATALOGO = (
    ("sin_firma", "Quitar la firma",
     "Se borran los campos de firma: el archivo queda como un .vault de D3.",
     quitar_firma),
    ("cifrado", "Alterar 1 bit del cifrado",
     "Mallory cambia un bit del contenido cifrado en tránsito.",
     alterar_cifrado),
    ("firma_truncada", "Firma incompleta",
     "La firma Ed25519 se recorta a 63 de sus 64 bytes.",
     truncar_firma),
    ("huella_truncada", "Llave con hash incompleto",
     "El signer_id se recorta a 32 de sus 64 caracteres hexadecimales.",
     truncar_huella_firmante),
    ("suplantacion", "Suplantar al remitente",
     "Mallory vuelve a firmar el contenedor con su propia llave Ed25519.",
     suplantar_remitente),
)

ATAQUES = {clave: funcion for clave, _titulo, _texto, funcion in CATALOGO}

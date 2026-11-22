"""D5 - Integración de firmas digitales (Ed25519) con D2/D3.

    Cifrar (D2) -> Metadatos + destinatarios ECIES (D3) -> FIRMAR -> Guardar
    Leer -> 1. FIRMA completa y válida -> 2. LLAVE con hash completo
         -> 3. formato D3 -> 4. firmante no revocado (D6)
         -> 5. clave del destinatario activa (D6) -> 6. descifrar

El contenedor firmado es el contenedor v3 de D3 más tres campos de nivel
superior: signer_id, signature_algorithm y signature. D2/D3 no se modifican:
antes de llamar a D3 se quitan esos tres campos (D3 rechaza campos extra).
Por eso D3 NO puede abrir un contenedor firmado directamente, y un atacante
que borre la firma no logra que se salte la verificación.

IMPORTANTE: el sistema integrado (app.py, demo_final.py) abre los .vault
SOLO con `abrir_archivo_firmado` / `descifrar_contenedor_firmado`: un archivo
sin firma se rechaza siempre. `abrir_archivo_compartido` (D3) queda como
primitiva interna de las pruebas y demos históricas de D3/D4.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vault.persistencia import escribir_atomico
from vault.shared_container import validar_contenedor
from vault.sharing import cifrar_para_destinatarios, descifrar_como_destinatario
from vault.signatures import (
    CAMPOS_FIRMA,
    ErrorFirma,
    firmar_contenedor,
    verificar_contenedor,
)

__all__ = [
    "firmar_contenedor_compartido",
    "cifrar_y_firmar",
    "verificar_contenedor_firmado",
    "descifrar_contenedor_firmado",
    "firmar_y_compartir_archivo",
    "verificar_archivo_firmado",
    "abrir_archivo_firmado",
    "leer_contenedor",
]


# --------------------------------------------------------------------------
# Lectura / escritura
# --------------------------------------------------------------------------
def _sin_duplicados(pares):
    objeto = {}
    for clave, valor in pares:
        if clave in objeto:
            raise ValueError("clave JSON duplicada")
        objeto[clave] = valor
    return objeto


def _constante_invalida(nombre):
    raise ValueError(f"constante JSON no permitida: {nombre}")


def leer_contenedor(ruta) -> dict:
    """JSON sin claves duplicadas ni NaN/Infinity. Todo error -> ErrorFirma.

    Solo lee: NO verifica la firma (eso lo hace verificar_contenedor_firmado).
    """
    try:
        datos = json.loads(
            Path(ruta).read_text(encoding="utf-8"),
            object_pairs_hook=_sin_duplicados,
            parse_constant=_constante_invalida,
        )
    except (OSError, ValueError, RecursionError):
        raise ErrorFirma("Contenedor ilegible o malformado.") from None
    if not isinstance(datos, dict):
        raise ErrorFirma("Contenedor ilegible o malformado.")
    return datos


def _guardar_json_atomico(contenedor: Mapping[str, Any], ruta) -> None:
    datos = json.dumps(
        contenedor, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    # El .vault va cifrado y firmado: está pensado para compartirse (0644).
    escribir_atomico(ruta, datos, modo=0o644)


# --------------------------------------------------------------------------
# Firmar (en memoria)
# --------------------------------------------------------------------------
def firmar_contenedor_compartido(
    contenedor: Mapping[str, Any], clave_firma: Ed25519PrivateKey
) -> dict:
    """Valida el contenedor v3 de D3 y devuelve una copia firmada."""
    validar_contenedor(contenedor)
    return firmar_contenedor(contenedor, clave_firma)


def cifrar_y_firmar(
    datos: bytes,
    nombre_archivo: str,
    destinatarios: dict,
    clave_firma: Ed25519PrivateKey,
) -> dict:
    """Encrypt -> Add metadata -> Sign. Devuelve el contenedor firmado."""
    contenedor = cifrar_para_destinatarios(datos, nombre_archivo, destinatarios)
    return firmar_contenedor_compartido(contenedor, clave_firma)


# --------------------------------------------------------------------------
# Verificar / abrir (en memoria)
# --------------------------------------------------------------------------
def verificar_contenedor_firmado(
    contenedor: Mapping[str, Any], clave_publica_firmante: Ed25519PublicKey
) -> dict:
    """Verifica la firma y devuelve el contenedor v3 interno (sin campos de
    firma), ya validado por D3. Lanza ErrorFirma si la firma no es válida."""
    verificar_contenedor(contenedor, clave_publica_firmante)  # 1-2) firma, llave
    interno = {k: v for k, v in contenedor.items() if k not in CAMPOS_FIRMA}
    validar_contenedor(interno)                               # 3) formato D3
    return interno


def descifrar_contenedor_firmado(
    contenedor: Mapping[str, Any],
    clave_privada,
    id_usuario: str,
    clave_publica_firmante: Ed25519PublicKey,
    gestor_claves,
) -> bytes:
    """Verifica firma, estado de las claves y solo entonces descifra con D3.

    `gestor_claves` es obligatorio: sin él no habría forma de rechazar una
    clave revocada, y una revocación que se puede omitir no revoca nada.
    """
    if gestor_claves is None:
        raise ValueError("Se requiere un gestor de claves para validar la revocación.")

    # 1-3. Firma completa y válida -> llave con hash completo -> formato D3.
    interno = verificar_contenedor_firmado(contenedor, clave_publica_firmante)

    # 4. La llave de firma del remitente no debe estar revocada (D6).
    gestor_claves.validar_firmante(contenedor["signer_id"])

    # 5. La clave del destinatario debe ser la activa registrada (D6).
    gestor_claves.validar_clave_para_uso(id_usuario, clave_privada)

    # 6. Descifrar únicamente si todas las validaciones pasan.
    return descifrar_como_destinatario(interno, clave_privada, id_usuario)


# --------------------------------------------------------------------------
# Operaciones sobre archivos en disco
# --------------------------------------------------------------------------
def firmar_y_compartir_archivo(
    ruta_origen, ruta_vault, destinatarios: dict, clave_firma: Ed25519PrivateKey
) -> None:
    origen = Path(ruta_origen)
    firmado = cifrar_y_firmar(
        origen.read_bytes(), origen.name, destinatarios, clave_firma
    )
    _guardar_json_atomico(firmado, ruta_vault)


def verificar_archivo_firmado(
    ruta_vault, clave_publica_firmante: Ed25519PublicKey
) -> dict:
    return verificar_contenedor_firmado(
        leer_contenedor(ruta_vault), clave_publica_firmante
    )


def abrir_archivo_firmado(
    ruta_vault,
    clave_privada,
    id_usuario: str,
    clave_publica_firmante: Ed25519PublicKey,
    gestor_claves,
    ruta_salida=None,
) -> bytes:
    """Verifica firma y revocación antes de descifrar."""

    datos = descifrar_contenedor_firmado(
        leer_contenedor(ruta_vault),
        clave_privada,
        id_usuario,
        clave_publica_firmante,
        gestor_claves=gestor_claves,
    )

    if ruta_salida is not None:  # solo se escribe tras pasar TODAS las verificaciones
        escribir_atomico(ruta_salida, datos, modo=0o600)

    return datos
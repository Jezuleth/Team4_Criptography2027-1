
"""D6: respaldo y recuperación de almacenes de claves."""

import os
from pathlib import Path

from vault.keystore import (
    ErrorKeystore,
    cargar_keystore,
    recuperar_clave_privada,
)


class ErrorBackup(Exception):
    """Error de respaldo o recuperación."""


def _validar_almacen(ruta, password):
    """Comprueba que el keystore puede descifrarse."""
    almacen = cargar_keystore(ruta)
    recuperar_clave_privada(almacen, password)
    return almacen


def _guardar_exclusivo(ruta, datos):
    """Crea un archivo nuevo sin sobrescribir otro."""
    ruta = Path(ruta)
    ruta.parent.mkdir(parents=True, exist_ok=True)

    descriptor = os.open(
        ruta,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
        0o600,
    )

    with os.fdopen(descriptor, "wb") as archivo:
        archivo.write(datos)


def crear_backup(ruta_origen, ruta_backup, password):
    """
    Respalda un keystore cifrado.

    El respaldo conserva la protección AES-GCM original.
    """
    try:
        origen = Path(ruta_origen)
        destino = Path(ruta_backup)

        if origen.resolve() == destino.resolve():
            raise ErrorBackup(
                "Origen y destino deben ser diferentes."
            )

        _validar_almacen(origen, password)

        datos = origen.read_bytes()
        _guardar_exclusivo(destino, datos)

        return destino

    except (OSError, ErrorKeystore) as exc:
        raise ErrorBackup(
            "No se pudo crear el respaldo."
        ) from exc


def restaurar_backup(ruta_backup, ruta_destino, password):
    """
    Restaura un keystore después de validar su contraseña.

    Nunca sobrescribe una identidad existente.
    """
    try:
        origen = Path(ruta_backup)
        destino = Path(ruta_destino)

        if origen.resolve() == destino.resolve():
            raise ErrorBackup(
                "Origen y destino deben ser diferentes."
            )

        _validar_almacen(origen, password)

        datos = origen.read_bytes()
        _guardar_exclusivo(destino, datos)

        return destino

    except (OSError, ErrorKeystore) as exc:
        raise ErrorBackup(
            "No se pudo restaurar el respaldo."
        ) from exc


def verificar_backup(ruta_backup, password):
    """Verifica la integridad y la contraseña del respaldo."""
    try:
        _validar_almacen(ruta_backup, password)
        return True
    except (OSError, ErrorKeystore, ValueError):
        return False

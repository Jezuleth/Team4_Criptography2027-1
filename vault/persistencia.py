"""Escritura duradera y atómica de archivos del vault.

Un único punto para todo lo que el sistema integrado guarda en disco
(historial de claves D6, contenedores firmados .vault y directorio de
claves públicas), para que ninguna escritura quede a medias:

    temporal en el MISMO directorio -> fsync -> os.replace atómico
    -> fsync del directorio (POSIX)

Si algo falla, el destino conserva su contenido anterior y el temporal
se borra.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path


def escribir_atomico(ruta, datos: bytes, modo: int = 0o600) -> Path:
    """Escribe `datos` en `ruta` de forma atómica y persistente.

    `modo` son los permisos finales en POSIX (0o600 por defecto: solo el
    dueño). En Windows los permisos los controla el sistema (ACL).
    """
    if not isinstance(datos, (bytes, bytearray)):
        raise TypeError("Los datos a escribir deben ser bytes.")

    destino = Path(ruta)
    destino.parent.mkdir(parents=True, exist_ok=True)

    descriptor, temporal = tempfile.mkstemp(
        dir=destino.parent, prefix=destino.name + ".", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as archivo:
            archivo.write(datos)
            archivo.flush()
            os.fsync(archivo.fileno())
        if os.name == "posix":
            os.chmod(temporal, modo)
        os.replace(temporal, destino)
    except BaseException:
        Path(temporal).unlink(missing_ok=True)
        raise

    if os.name == "posix":  # persistir también la entrada del directorio
        fd_dir = os.open(destino.parent, os.O_RDONLY)
        try:
            os.fsync(fd_dir)
        finally:
            os.close(fd_dir)

    return destino

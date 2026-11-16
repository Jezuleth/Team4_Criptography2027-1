
"""
D6 - Gestión del ciclo de vida de claves.

Responsabilidades:
- Generación de claves de usuario.
- Registro de identidad mediante fingerprint.
- Control de versiones y rotación.
- Revocación ante compromiso.
- Gestión del estado de las claves.

La protección y persistencia cifrada de las claves
se delegará al módulo keystore.py.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class ErrorCicloVida(Exception):
    """Error relacionado con el ciclo de vida de claves."""


@dataclass
class RegistroClave:
    usuario: str
    fingerprint: str
    version: int
    creada: str
    estado: str = "activa"
    motivo_revocacion: Optional[str] = None


class GestorCicloVida:
    """
    Administra las claves privadas de los usuarios.

    Las claves privadas se mantienen en memoria únicamente
    durante su utilización. Su almacenamiento persistente
    debe realizarse mediante keystore.py.
    """

    def __init__(self):
        self._registros = {}
        self._claves_activas = {}
        self._versiones = {}
        self._lock = threading.RLock()

    @staticmethod
    def _fingerprint(clave_publica) -> str:
        der = clave_publica.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    def generar_clave(self, usuario: str):
        """Genera una nueva clave privada EC para un usuario."""

        if not isinstance(usuario, str) or not usuario.strip():
            raise ErrorCicloVida("Usuario inválido.")

        with self._lock:
            clave = ec.generate_private_key(ec.SECP256K1())
            fingerprint = self._fingerprint(clave.public_key())

            version = self._versiones.get(usuario, 0) + 1

            registro = RegistroClave(
                usuario=usuario,
                fingerprint=fingerprint,
                version=version,
                creada=datetime.now(timezone.utc).isoformat(),
            )

            anterior = self._registros.get(usuario)

            if anterior and anterior.estado == "activa":
                anterior.estado = "rotada"

            self._registros[usuario] = registro
            self._claves_activas[usuario] = clave
            self._versiones[usuario] = version

            return clave, registro

    def obtener_clave(self, usuario: str):
        """Obtiene la clave activa de un usuario."""

        with self._lock:
            registro = self._registros.get(usuario)

            if registro is None or registro.estado != "activa":
                raise ErrorCicloVida("No existe una clave activa.")

            clave = self._claves_activas.get(usuario)

            if clave is None:
                raise ErrorCicloVida(
                    "La clave no está cargada. Debe recuperarse "
                    "mediante el keystore."
                )

            if self._fingerprint(clave.public_key()) != registro.fingerprint:
                raise ErrorCicloVida("La identidad de la clave no coincide.")

            return clave

    def rotar_clave(self, usuario: str):
        """
        Genera una nueva versión y desactiva la anterior.

        La migración de archivos compartidos debe gestionarse
        por separado.
        """
        return self.generar_clave(usuario)

    def revocar_clave(self, usuario: str, motivo: str):
        """Revoca una clave ante sospecha de compromiso."""

        if not isinstance(motivo, str) or not motivo.strip():
            raise ErrorCicloVida("Debe especificarse un motivo.")

        with self._lock:
            registro = self._registros.get(usuario)

            if registro is None:
                raise ErrorCicloVida("Usuario sin claves registradas.")

            registro.estado = "revocada"
            registro.motivo_revocacion = motivo

            self._claves_activas.pop(usuario, None)

    def obtener_registro(self, usuario: str):
        """Consulta los metadatos de la clave sin revelar la privada."""

        with self._lock:
            registro = self._registros.get(usuario)

            if registro is None:
                raise ErrorCicloVida("Registro inexistente.")

            return RegistroClave(
                usuario=registro.usuario,
                fingerprint=registro.fingerprint,
                version=registro.version,
                creada=registro.creada,
                estado=registro.estado,
                motivo_revocacion=registro.motivo_revocacion,
            )

    def descargar_clave_de_memoria(self, usuario: str):
        """Elimina la referencia a la clave privada en memoria."""

        with self._lock:
            self._claves_activas.pop(usuario, None)
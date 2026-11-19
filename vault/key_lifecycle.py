
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
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
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

    def __init__(self, ruta_estado=None, password_estado=None):
        self._registros = {}
        self._claves_activas = {}
        self._versiones = {}
        self._historial_claves = {}
        self._lock = threading.RLock()

        self._ruta_estado = (
            Path(ruta_estado) if ruta_estado is not None else None
        )
        self._password_estado = password_estado

        if self._ruta_estado is not None:
            if (
                not isinstance(password_estado, str)
                or len(password_estado) < 12
            ):
                raise ErrorCicloVida(
                    "Se requiere una contraseña de al menos 12 caracteres "
                    "para proteger el historial."
                )

            if self._ruta_estado.exists():
                self._cargar_estado()

    def _guardar_estado(self):
        """Guarda el historial cifrado y autenticado."""
        if self._ruta_estado is None:
            return

        registros = {
            usuario: vars(registro).copy()
            for usuario, registro in self._registros.items()
        }

        datos = json.dumps(
            {
                "registros": registros,
                "versiones": self._versiones,
                "historial": self._historial_claves,
            },
            sort_keys=True,
        ).encode("utf-8")

        salt = os.urandom(16)
        nonce = os.urandom(12)

        clave = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
        ).derive(self._password_estado.encode("utf-8"))

        cifrado = AESGCM(clave).encrypt(
            nonce, datos, b"D6-LIFECYCLE-v1"
        )

        import base64

        contenido = {
            "version": 1,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(cifrado).decode("ascii"),
        }

        self._ruta_estado.parent.mkdir(
            parents=True, exist_ok=True
        )

        temporal = self._ruta_estado.with_name(
            self._ruta_estado.name + ".tmp"
        )

        try:
            with open(temporal, "x", encoding="utf-8") as archivo:
                json.dump(contenido, archivo, indent=2)

            os.replace(temporal, self._ruta_estado)
        finally:
            temporal.unlink(missing_ok=True)

    def _cargar_estado(self):
        """Recupera el historial al reiniciar."""
        import base64

        try:
            with open(self._ruta_estado, "r", encoding="utf-8") as archivo:
                contenido = json.load(archivo)

            if contenido["version"] != 1:
                raise ErrorCicloVida("Versión de historial incompatible.")

            salt = base64.b64decode(
                contenido["salt"], validate=True
            )
            nonce = base64.b64decode(
                contenido["nonce"], validate=True
            )
            cifrado = base64.b64decode(
                contenido["ciphertext"], validate=True
            )

            if len(salt) != 16 or len(nonce) != 12:
                raise ErrorCicloVida("Parámetros inválidos.")

            clave = Scrypt(
                salt=salt,
                length=32,
                n=2**14,
                r=8,
                p=1,
            ).derive(self._password_estado.encode("utf-8"))

            datos = AESGCM(clave).decrypt(
                nonce, cifrado, b"D6-LIFECYCLE-v1"
            )

            estado = json.loads(datos)

            registros = {
                usuario: RegistroClave(**registro)
                for usuario, registro in estado["registros"].items()
            }
            versiones = estado["versiones"]

            if not isinstance(versiones, dict):
                raise ValueError("Versiones inválidas.")

            self._registros = registros
            self._versiones = versiones
            self._historial_claves = estado.get("historial_claves", {})

        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ErrorCicloVida(
                "No se pudo recuperar el historial."
            ) from exc
        except Exception as exc:
            raise ErrorCicloVida(
                "Contraseña incorrecta o historial alterado."
            ) from exc
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
            self._guardar_estado()

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
            self._guardar_estado()

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

    def validar_clave_para_uso(self, usuario, clave_privada):
        """Autoriza únicamente la clave activa registrada."""
        with self._lock:
            registro = self._registros.get(usuario)

            if registro is None:
                raise ErrorCicloVida(
                    "El usuario no tiene una clave registrada."
                )

            if registro.estado != "activa":
                raise ErrorCicloVida(
                    "La clave está revocada o no está activa."
                )

            fingerprint = self._fingerprint(
                clave_privada.public_key()
            )

            if fingerprint != registro.fingerprint:
                raise ErrorCicloVida(
                    "La clave no coincide con la identidad activa."
                )

            return True


    def registrar_clave_existente(self, usuario, clave_privada):
        """Registra una clave ECIES existente sin generar otra."""
        from cryptography.hazmat.primitives.asymmetric import ec

        if not isinstance(usuario, str) or not usuario.strip():
            raise ErrorCicloVida("Usuario inválido.")

        if not isinstance(clave_privada, ec.EllipticCurvePrivateKey):
            raise ErrorCicloVida("Clave privada inválida.")

        if not isinstance(clave_privada.curve, ec.SECP256K1):
            raise ErrorCicloVida("Solo se admite secp256k1.")

        with self._lock:
            if usuario in self._registros:
                raise ErrorCicloVida(
                    "El usuario ya tiene una identidad registrada."
                )

            fingerprint = self._fingerprint(clave_privada.public_key())

            registro = RegistroClave(
                usuario=usuario,
                fingerprint=fingerprint,
                version=1,
                creada=datetime.now(timezone.utc).isoformat(),
            )

            self._registros[usuario] = registro
            self._claves_activas[usuario] = clave_privada
            self._versiones[usuario] = 1

            self._guardar_estado()

            return self.obtener_registro(usuario)

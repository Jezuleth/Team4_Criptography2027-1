"""
D6 - Gestión del ciclo de vida de claves.

Responsabilidades:
- Generación de claves de usuario (ECIES secp256k1).
- Registro de identidad mediante fingerprint (SHA-256 completo del DER SPKI).
- Control de versiones, rotación e historial de claves anteriores.
- Revocación ante compromiso, PERSISTENTE en disco: el estado se guarda
  cifrado y autenticado (scrypt + AES-256-GCM) con escritura atómica y
  fsync. Las huellas revocadas (ECIES y de firma Ed25519) no pueden volver
  a registrarse ni a usarse aunque alguien restaure un respaldo del keystore.

La protección cifrada de cada clave privada la realiza keystore.py.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from vault.keystore import ErrorKeystore, _derivar_clave, validar_password
from vault.persistencia import escribir_atomico

VERSION_ESTADO = 1
SCRYPT_N_ESTADO = 2**14
AAD_ESTADO = b"D6-LIFECYCLE-v1"
_HUELLA_COMPLETA = re.compile(r"[0-9a-f]{64}")


class ErrorCicloVida(Exception):
    """Error relacionado con el ciclo de vida de claves."""


class FirmanteRevocado(ErrorCicloVida):
    """La llave de firma del remitente fue revocada."""


@dataclass
class RegistroClave:
    usuario: str
    fingerprint: str
    version: int
    creada: str
    estado: str = "activa"
    motivo_revocacion: Optional[str] = None
    huella_firma: Optional[str] = None


def _validar_huella(huella) -> str:
    if not isinstance(huella, str) or _HUELLA_COMPLETA.fullmatch(huella) is None:
        raise ErrorCicloVida("La huella debe ser un SHA-256 completo (64 hex).")
    return huella


class GestorCicloVida:
    """
    Administra el estado de las claves de los usuarios.

    Con `ruta_estado` el estado es persistente (recomendado y usado por la
    aplicación). Sin ruta el gestor vive solo en memoria (útil en pruebas):
    en ese caso una revocación desaparece al cerrar el programa.
    """

    def __init__(self, ruta_estado=None, password_estado=None):
        self._registros: dict[str, RegistroClave] = {}
        self._claves_activas = {}
        self._versiones: dict[str, int] = {}
        self._historial_claves: dict[str, list] = {}
        self._huellas_revocadas: set[str] = set()
        self._lock = threading.RLock()

        self._ruta_estado = Path(ruta_estado) if ruta_estado is not None else None
        self._password_estado = password_estado

        if self._ruta_estado is None:
            return

        if not isinstance(password_estado, str) or not password_estado:
            raise ErrorCicloVida("Se requiere la contraseña del historial.")

        if self._ruta_estado.exists():
            self._cargar_estado()
        else:
            # Historial nuevo: se aplica la misma política que a los keystores.
            try:
                validar_password(password_estado)
            except ErrorKeystore as exc:
                raise ErrorCicloVida(str(exc)) from exc

    # ------------------------------------------------------------------
    # Persistencia
    # ------------------------------------------------------------------
    def _derivar(self, salt: bytes) -> bytes:
        return _derivar_clave(self._password_estado, salt, n=SCRYPT_N_ESTADO)

    def _guardar_estado(self):
        """Guarda el estado cifrado y autenticado (escritura duradera)."""
        if self._ruta_estado is None:
            return

        estado = json.dumps(
            {
                "registros": {u: asdict(r) for u, r in self._registros.items()},
                "versiones": self._versiones,
                "historial_claves": self._historial_claves,
                "huellas_revocadas": sorted(self._huellas_revocadas),
            },
            sort_keys=True,
        ).encode("utf-8")

        salt = os.urandom(16)
        nonce = os.urandom(12)
        cifrado = AESGCM(self._derivar(salt)).encrypt(nonce, estado, AAD_ESTADO)

        contenido = {
            "version": VERSION_ESTADO,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(cifrado).decode("ascii"),
        }
        self._escribir_duradero(json.dumps(contenido, indent=2).encode("utf-8"))

    def _escribir_duradero(self, datos: bytes) -> None:
        """Temporal 0600 -> fsync -> os.replace atómico -> fsync del directorio."""
        escribir_atomico(self._ruta_estado, datos, modo=0o600)

    def _cargar_estado(self):
        """Recupera el estado al reiniciar."""
        try:
            contenido = json.loads(self._ruta_estado.read_text(encoding="utf-8"))
            if contenido["version"] != VERSION_ESTADO:
                raise ErrorCicloVida("Versión de historial incompatible.")

            salt = base64.b64decode(contenido["salt"], validate=True)
            nonce = base64.b64decode(contenido["nonce"], validate=True)
            cifrado = base64.b64decode(contenido["ciphertext"], validate=True)
            if len(salt) != 16 or len(nonce) != 12:
                raise ErrorCicloVida("Parámetros inválidos.")

            estado = json.loads(
                AESGCM(self._derivar(salt)).decrypt(nonce, cifrado, AAD_ESTADO)
            )

            registros = {
                usuario: RegistroClave(**registro)
                for usuario, registro in estado["registros"].items()
            }
            versiones = estado["versiones"]
            historial = estado.get("historial_claves", {})
            revocadas = estado.get("huellas_revocadas", [])
            if not all(isinstance(x, dict) for x in (versiones, historial)):
                raise ValueError("Estructura de historial inválida.")
            if not isinstance(revocadas, list):
                raise ValueError("Lista de revocación inválida.")

        except InvalidTag as exc:
            raise ErrorCicloVida(
                "Contraseña incorrecta o historial alterado."
            ) from exc
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ErrorCicloVida("No se pudo recuperar el historial.") from exc

        self._registros = registros
        self._versiones = versiones
        self._historial_claves = historial
        # Compatibilidad con historiales anteriores (sin lista explícita).
        self._huellas_revocadas = set(revocadas) | {
            huella
            for r in registros.values()
            if r.estado == "revocada"
            for huella in (r.fingerprint, r.huella_firma)
            if huella
        }

    # ------------------------------------------------------------------
    # Utilidades internas
    # ------------------------------------------------------------------
    @staticmethod
    def _fingerprint(clave_publica) -> str:
        der = clave_publica.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return hashlib.sha256(der).hexdigest()

    def _archivar(self, registro: RegistroClave) -> None:
        self._historial_claves.setdefault(registro.usuario, []).append(
            asdict(registro)
        )

    def _exigir_activa(self, usuario: str, huella: str) -> RegistroClave:
        """La huella presentada debe ser la de la clave ACTIVA del usuario."""
        registro = self._registros.get(usuario)
        if registro is None:
            raise ErrorCicloVida("El usuario no tiene una clave registrada.")
        if registro.estado != "activa":
            raise ErrorCicloVida("La clave está revocada o no está activa.")
        if not hmac.compare_digest(huella, registro.fingerprint):
            raise ErrorCicloVida("La clave no coincide con la identidad activa.")
        return registro

    # ------------------------------------------------------------------
    # Altas, rotación y revocación
    # ------------------------------------------------------------------
    def generar_clave(self, usuario: str):
        """Genera una nueva clave privada EC para un usuario (o la rota)."""
        if not isinstance(usuario, str) or not usuario.strip():
            raise ErrorCicloVida("Usuario inválido.")

        with self._lock:
            clave = ec.generate_private_key(ec.SECP256K1())
            anterior = self._registros.get(usuario)
            heredada = None

            if anterior is not None:
                if anterior.estado == "activa":
                    anterior.estado = "rotada"
                    heredada = anterior.huella_firma  # la firma no cambia al rotar
                self._archivar(anterior)

            version = self._versiones.get(usuario, 0) + 1
            registro = RegistroClave(
                usuario=usuario,
                fingerprint=self._fingerprint(clave.public_key()),
                version=version,
                creada=datetime.now(timezone.utc).isoformat(),
                huella_firma=heredada,
            )

            self._registros[usuario] = registro
            self._claves_activas[usuario] = clave
            self._versiones[usuario] = version
            self._guardar_estado()

            return clave, registro

    def rotar_clave(self, usuario: str):
        """Genera una nueva versión y desactiva la anterior.

        La migración de archivos compartidos debe gestionarse por separado.
        """
        return self.generar_clave(usuario)

    def registrar_clave_existente(self, usuario, clave_privada, huella_firma=None):
        """Registra una clave ECIES existente (y opcionalmente la huella de
        su llave de firma Ed25519). Rechaza claves que ya fueron revocadas."""
        if not isinstance(usuario, str) or not usuario.strip():
            raise ErrorCicloVida("Usuario inválido.")
        if not isinstance(clave_privada, ec.EllipticCurvePrivateKey):
            raise ErrorCicloVida("Clave privada inválida.")
        if not isinstance(clave_privada.curve, ec.SECP256K1):
            raise ErrorCicloVida("Solo se admite secp256k1.")
        if huella_firma is not None:
            _validar_huella(huella_firma)

        with self._lock:
            if usuario in self._registros:
                raise ErrorCicloVida("El usuario ya tiene una identidad registrada.")

            fingerprint = self._fingerprint(clave_privada.public_key())
            if {fingerprint, huella_firma} & self._huellas_revocadas:
                raise ErrorCicloVida(
                    "Esta clave fue revocada y no puede volver a registrarse."
                )

            self._registros[usuario] = RegistroClave(
                usuario=usuario,
                fingerprint=fingerprint,
                version=1,
                creada=datetime.now(timezone.utc).isoformat(),
                huella_firma=huella_firma,
            )
            self._claves_activas[usuario] = clave_privada
            self._versiones[usuario] = 1
            self._guardar_estado()

            return self.obtener_registro(usuario)

    def vincular_huella_firma(self, usuario, clave_privada, huella_firma):
        """Completa la huella de firma de un registro anterior que no la tenía.

        Exige la clave privada ECIES activa como prueba de posesión.
        """
        _validar_huella(huella_firma)
        with self._lock:
            registro = self._exigir_activa(
                usuario, self._fingerprint(clave_privada.public_key())
            )
            if huella_firma in self._huellas_revocadas:
                raise FirmanteRevocado("La llave de firma fue revocada.")
            if registro.huella_firma is None:
                registro.huella_firma = huella_firma
                self._guardar_estado()
            elif not hmac.compare_digest(registro.huella_firma, huella_firma):
                raise ErrorCicloVida("La llave de firma no coincide con la registrada.")

    def revocar_clave(self, usuario: str, motivo: str):
        """Revoca la identidad del usuario (clave ECIES y llave de firma)."""
        if not isinstance(motivo, str) or not motivo.strip():
            raise ErrorCicloVida("Debe especificarse un motivo.")

        with self._lock:
            registro = self._registros.get(usuario)
            if registro is None:
                raise ErrorCicloVida("Usuario sin claves registradas.")

            registro.estado = "revocada"
            registro.motivo_revocacion = motivo
            self._huellas_revocadas.add(registro.fingerprint)
            if registro.huella_firma:
                self._huellas_revocadas.add(registro.huella_firma)
            self._claves_activas.pop(usuario, None)

            # La revocación queda activa en memoria aunque el disco falle
            # (falla cerrado), pero se avisa: sin disco no sería persistente.
            try:
                self._guardar_estado()
            except OSError as exc:
                raise ErrorCicloVida(
                    "La clave quedó revocada en memoria, pero no se pudo "
                    "guardar la revocación en disco."
                ) from exc

    # ------------------------------------------------------------------
    # Consultas y validaciones de uso
    # ------------------------------------------------------------------
    def existe_registro(self, usuario: str) -> bool:
        with self._lock:
            return usuario in self._registros

    def obtener_registro(self, usuario: str):
        """Consulta los metadatos de la clave sin revelar la privada."""
        with self._lock:
            registro = self._registros.get(usuario)
            if registro is None:
                raise ErrorCicloVida("Registro inexistente.")
            return RegistroClave(**asdict(registro))

    def obtener_historial(self, usuario: str) -> list:
        """Versiones anteriores (rotadas o revocadas) del usuario."""
        with self._lock:
            return [dict(r) for r in self._historial_claves.get(usuario, [])]

    def esta_revocada(self, huella: str) -> bool:
        with self._lock:
            return huella in self._huellas_revocadas

    def obtener_clave(self, usuario: str):
        """Obtiene la clave activa cargada en memoria de un usuario."""
        with self._lock:
            clave = self._claves_activas.get(usuario)
            if clave is None:
                raise ErrorCicloVida(
                    "No hay una clave activa cargada; debe recuperarse "
                    "mediante el keystore."
                )
            self._exigir_activa(usuario, self._fingerprint(clave.public_key()))
            return clave

    def descargar_clave_de_memoria(self, usuario: str):
        """Elimina la referencia a la clave privada en memoria."""
        with self._lock:
            self._claves_activas.pop(usuario, None)

    def validar_clave_para_uso(self, usuario, clave_privada):
        """Autoriza únicamente la clave privada activa registrada."""
        with self._lock:
            self._exigir_activa(usuario, self._fingerprint(clave_privada.public_key()))
            return True

    def validar_clave_publica_activa(self, usuario, clave_publica):
        """Antes de cifrar PARA alguien: su clave pública debe ser la activa."""
        with self._lock:
            self._exigir_activa(usuario, self._fingerprint(clave_publica))
            return True

    def validar_firmante(self, huella_firma) -> bool:
        """La llave de firma (signer_id) no debe estar revocada."""
        with self._lock:
            if huella_firma in self._huellas_revocadas:
                raise FirmanteRevocado(
                    "La llave de firma del remitente fue revocada."
                )
            return True

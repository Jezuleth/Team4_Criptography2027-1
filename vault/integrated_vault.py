"""Sistema integrado D2 + D3 + D5 + D6 del Secure Digital Document Vault.

Único punto de entrada de la lógica que usan app.py y demo_final.py.

Repositorio de llaves (una carpeta por identidad dentro de la carpeta base):

    <base>/historial_claves.enc       estado D6 cifrado (revocaciones, versiones)
    <base>/<usuario>/ecies.keystore   clave privada ECIES secp256k1 (cifrada)
    <base>/<usuario>/firma.keystore   clave privada Ed25519 (cifrada)
    <base>/<usuario>/publica.json     directorio público: PEM + huellas

Flujo de envío:   cifrar (AES-256-GCM) -> envolver clave (ECIES) -> FIRMAR
Flujo de lectura: firma completa -> llave con hash completo -> formato
                  -> firmante no revocado -> clave del destinatario activa
                  -> descifrar.  Un archivo SIN firma nunca se descifra.
"""

from __future__ import annotations

import hmac
import json
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vault.key_lifecycle import ErrorCicloVida, GestorCicloVida
from vault.keystore import (
    cargar_keystore,
    eliminar_keystore,
    guardar_keystore,
    proteger_clave_privada,
    recuperar_clave_privada,
    validar_password,
)
from vault.persistencia import escribir_atomico
from vault.public_key import (
    cargar_clave_publica,
    generar_par_claves,
    huella_clave_publica,
    serializar_clave_publica,
    validar_clave_publica,
    verificar_huella,
)
from vault.signatures import (
    CAMPOS_FIRMA,
    ErrorFirma,
    exportar_clave_publica_firma,
    generar_par_claves_firma,
    huella_clave_firma,
    importar_clave_publica_firma,
)
from vault.signed_sharing import abrir_archivo_firmado, firmar_y_compartir_archivo

ARCHIVO_ECIES = "ecies.keystore"
ARCHIVO_FIRMA = "firma.keystore"
ARCHIVO_PUBLICO = "publica.json"
ARCHIVO_HISTORIAL = "historial_claves.enc"

# Nombre de usuario = nombre de carpeta: solo caracteres seguros en cualquier SO.
_NOMBRE_VALIDO = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")


class DirectorioAlterado(ValueError):
    """El directorio público no coincide con sus huellas o con el historial D6."""


def validar_nombre_usuario(usuario) -> str:
    if not isinstance(usuario, str) or _NOMBRE_VALIDO.fullmatch(usuario) is None:
        raise ValueError(
            "Usuario inválido: usa 1-32 caracteres en minúscula (a-z, 0-9, _ o -)."
        )
    return usuario


# --------------------------------------------------------------------------
# Claves privadas en el keystore
# --------------------------------------------------------------------------
def _serializar_privada(clave):
    """Serialización PKCS#8; el keystore aporta el cifrado."""
    return clave.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _recuperar_privada(ruta_keystore, password, tipo):
    datos = recuperar_clave_privada(cargar_keystore(ruta_keystore), password)
    clave = serialization.load_der_private_key(datos, password=None)

    if tipo == "ecies":
        if not isinstance(clave, ec.EllipticCurvePrivateKey):
            raise ValueError("La clave recuperada no es ECIES.")
        validar_clave_publica(clave.public_key())
    elif tipo == "firma":
        if not isinstance(clave, Ed25519PrivateKey):
            raise ValueError("La clave recuperada no es Ed25519.")
    else:
        raise ValueError("Tipo de clave no admitido.")

    return clave


# --------------------------------------------------------------------------
# Directorio público (sin secretos)
# --------------------------------------------------------------------------
def _guardar_directorio_publico(carpeta, usuario, publica_ecies, publica_firma):
    registro = {
        "version": 1,
        "usuario": usuario,
        "ecies_pem": serializar_clave_publica(publica_ecies).decode("ascii"),
        "firma_pem": exportar_clave_publica_firma(publica_firma).decode("ascii"),
        "huella_ecies": huella_clave_publica(publica_ecies),
        "huella_firma": huella_clave_firma(publica_firma),
    }
    escribir_atomico(
        Path(carpeta) / ARCHIVO_PUBLICO,
        json.dumps(registro, indent=2, sort_keys=True).encode("utf-8"),
        modo=0o644,
    )


def cargar_identidad_publica(carpeta, gestor_claves=None) -> dict:
    """Lee el directorio público de una identidad y comprueba su integridad.

    Las huellas guardadas deben coincidir con las claves PEM y, si se pasa
    `gestor_claves`, con las registradas en el historial cifrado de D6
    (así se detecta un publica.json sustituido).
    """
    carpeta = Path(carpeta)
    try:
        datos = json.loads((carpeta / ARCHIVO_PUBLICO).read_text(encoding="utf-8"))
        usuario = datos["usuario"]
        publica_ecies = cargar_clave_publica(datos["ecies_pem"].encode("ascii"))
        publica_firma = importar_clave_publica_firma(datos["firma_pem"].encode("ascii"))
        huella_ecies = huella_clave_publica(publica_ecies)
        signer_id = huella_clave_firma(publica_firma)
        consistente = (
            usuario == carpeta.name
            and hmac.compare_digest(huella_ecies, datos["huella_ecies"])
            and hmac.compare_digest(signer_id, datos["huella_firma"])
        )
    except FileNotFoundError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError, ErrorFirma) as exc:
        raise DirectorioAlterado("Directorio público ilegible o dañado.") from exc

    if not consistente:
        raise DirectorioAlterado("El directorio público no coincide con sus huellas.")

    if gestor_claves is not None and gestor_claves.existe_registro(usuario):
        registro = gestor_claves.obtener_registro(usuario)
        if not hmac.compare_digest(huella_ecies, registro.fingerprint) or (
            registro.huella_firma is not None
            and not hmac.compare_digest(signer_id, registro.huella_firma)
        ):
            raise DirectorioAlterado(
                f"Las claves públicas de {usuario} no coinciden con el historial "
                "de claves: posible sustitución."
            )

    return {
        "usuario": usuario,
        "clave_publica_ecies": publica_ecies,
        "clave_publica_firma": publica_firma,
        "huella_ecies": huella_ecies,
        "signer_id": signer_id,
    }


def listar_identidades(carpeta_base) -> list[str]:
    """Nombres de las identidades presentes en la carpeta base."""
    base = Path(carpeta_base)
    if not base.is_dir():
        return []
    marcas = (ARCHIVO_PUBLICO, ARCHIVO_ECIES, ARCHIVO_FIRMA)
    return sorted(
        c.name
        for c in base.iterdir()
        if c.is_dir()
        and _NOMBRE_VALIDO.fullmatch(c.name)
        and any((c / m).exists() for m in marcas)
    )


# --------------------------------------------------------------------------
# Identidades
# --------------------------------------------------------------------------
def abrir_gestor(carpeta_base, password) -> GestorCicloVida:
    """Gestor D6 persistente en <carpeta_base>/historial_claves.enc."""
    return GestorCicloVida(Path(carpeta_base) / ARCHIVO_HISTORIAL, password)


def registrar_claves_en_gestor(usuario, identidad, gestor_claves):
    """Registra (o sincroniza) en D6 la identidad ya recuperada. Idempotente.

    Si el usuario ya está registrado solo completa la huella de firma, con la
    clave ECIES activa como prueba de posesión.
    """
    huella_firma = huella_clave_firma(identidad["clave_firma"].public_key())
    if gestor_claves.existe_registro(usuario):
        gestor_claves.vincular_huella_firma(usuario, identidad["clave_ecies"], huella_firma)
        return gestor_claves.obtener_registro(usuario)
    return gestor_claves.registrar_clave_existente(
        usuario, identidad["clave_ecies"], huella_firma=huella_firma
    )


def crear_identidad(usuario, password, carpeta, gestor_claves=None):
    """Genera y protege las claves ECIES y Ed25519 del usuario.

    Con `gestor_claves` la identidad queda registrada en D6 en ese momento.
    """
    validar_nombre_usuario(usuario)
    validar_password(password)  # antes de escribir nada

    carpeta = Path(carpeta)
    ruta_ecies = carpeta / ARCHIVO_ECIES
    ruta_firma = carpeta / ARCHIVO_FIRMA
    if ruta_ecies.exists() or ruta_firma.exists():
        raise FileExistsError("La identidad ya tiene archivos de claves.")
    if gestor_claves is not None and gestor_claves.existe_registro(usuario):
        raise ErrorCicloVida("El usuario ya existe en el historial de claves.")
    carpeta.mkdir(parents=True, exist_ok=True)

    clave_ecies = generar_par_claves()
    clave_firma = generar_par_claves_firma()

    guardar_keystore(
        ruta_ecies,
        proteger_clave_privada(_serializar_privada(clave_ecies), password, f"{usuario}:ecies"),
    )
    guardar_keystore(
        ruta_firma,
        proteger_clave_privada(_serializar_privada(clave_firma), password, f"{usuario}:firma"),
    )
    _guardar_directorio_publico(carpeta, usuario, clave_ecies.public_key(), clave_firma.public_key())

    if gestor_claves is not None:
        registrar_claves_en_gestor(
            usuario, {"clave_ecies": clave_ecies, "clave_firma": clave_firma}, gestor_claves
        )

    return {
        "usuario": usuario,
        "clave_publica_ecies": clave_ecies.public_key(),
        "clave_publica_firma": clave_firma.public_key(),
        "huella_ecies": huella_clave_publica(clave_ecies.public_key()),
        "signer_id": huella_clave_firma(clave_firma.public_key()),
    }


def recuperar_identidad(password, carpeta):
    """Recupera las dos claves privadas protegidas.

    Si la identidad es anterior al directorio público, lo crea.
    """
    carpeta = Path(carpeta)
    identidad = {
        "clave_ecies": _recuperar_privada(carpeta / ARCHIVO_ECIES, password, "ecies"),
        "clave_firma": _recuperar_privada(carpeta / ARCHIVO_FIRMA, password, "firma"),
    }
    if not (carpeta / ARCHIVO_PUBLICO).exists():
        _guardar_directorio_publico(
            carpeta,
            carpeta.name,
            identidad["clave_ecies"].public_key(),
            identidad["clave_firma"].public_key(),
        )
    return identidad


def registrar_identidad_en_gestor(usuario, carpeta, password, gestor_claves):
    """Recupera la identidad del keystore y la registra en D6 (idempotente)."""
    return registrar_claves_en_gestor(
        usuario, recuperar_identidad(password, carpeta), gestor_claves
    )


def resumen_identidad(usuario, carpeta_base, gestor_claves) -> dict:
    """Estado legible de una identidad para la interfaz y la demo."""
    carpeta = Path(carpeta_base) / usuario
    resumen = {
        "usuario": usuario,
        "estado": "sin registrar",
        "motivo": None,
        "huella_ecies": None,
        "signer_id": None,
        "llaves_en_repositorio": (carpeta / ARCHIVO_ECIES).exists()
        and (carpeta / ARCHIVO_FIRMA).exists(),
        "error_directorio": None,
    }
    if gestor_claves.existe_registro(usuario):
        registro = gestor_claves.obtener_registro(usuario)
        resumen.update(
            estado=registro.estado,
            motivo=registro.motivo_revocacion,
            huella_ecies=registro.fingerprint,
            signer_id=registro.huella_firma,
        )
    try:
        publica = cargar_identidad_publica(carpeta, gestor_claves)
        resumen["huella_ecies"] = publica["huella_ecies"]
        resumen["signer_id"] = publica["signer_id"]
    except FileNotFoundError:
        resumen["error_directorio"] = "Sin directorio público (desbloquéala una vez)."
    except DirectorioAlterado as exc:
        resumen["error_directorio"] = str(exc)
    return resumen


# --------------------------------------------------------------------------
# Envío y recepción
# --------------------------------------------------------------------------
def enviar_archivo_con_claves(
    ruta_origen, ruta_vault, destinatarios, clave_firma, gestor_claves=None
):
    """Cifra para los destinatarios y firma con una clave ya desbloqueada.

    Con `gestor_claves` se exige que el firmante no esté revocado y que cada
    clave pública destino sea la ACTIVA del usuario (no se cifra para una
    identidad revocada).
    """
    if not destinatarios:
        raise ValueError("Debe existir al menos un destinatario.")

    if gestor_claves is not None:
        gestor_claves.validar_firmante(huella_clave_firma(clave_firma.public_key()))
        for usuario, clave_publica in destinatarios.items():
            gestor_claves.validar_clave_publica_activa(usuario, clave_publica)

    firmar_y_compartir_archivo(ruta_origen, ruta_vault, destinatarios, clave_firma)
    return Path(ruta_vault)


def enviar_archivo(
    ruta_origen,
    ruta_vault,
    destinatarios,
    carpeta_remitente,
    password_remitente,
    gestor_claves=None,
):
    """Cifra para destinatarios y firma con la identidad del remitente."""
    identidad = recuperar_identidad(password_remitente, carpeta_remitente)
    return enviar_archivo_con_claves(
        ruta_origen, ruta_vault, destinatarios, identidad["clave_firma"], gestor_claves
    )


def enviar_archivo_verificado(
    ruta_origen,
    ruta_vault,
    destinatarios,
    huellas_confiables,
    carpeta_remitente,
    password_remitente,
    gestor_claves=None,
):
    """Verifica las huellas (canal confiable) antes de cifrar y firmar."""
    if not destinatarios:
        raise ValueError("Debe existir al menos un destinatario.")
    if set(destinatarios) != set(huellas_confiables):
        raise ValueError("Cada destinatario debe tener una huella confiable.")

    for usuario, clave_publica in destinatarios.items():
        verificar_huella(clave_publica, huellas_confiables[usuario])

    return enviar_archivo(
        ruta_origen,
        ruta_vault,
        destinatarios,
        carpeta_remitente,
        password_remitente,
        gestor_claves,
    )


def identificar_remitente(contenedor, carpeta_base, gestor_claves=None) -> dict:
    """Busca en el directorio local la identidad cuyo signer_id firma el archivo.

    Solo localiza la clave pública: la verificación criptográfica la hace
    después `descifrar_contenedor_firmado` con esa clave. Un contenedor sin
    campos de firma se rechaza aquí mismo (nunca se descifra).
    """
    if not isinstance(contenedor, dict) or any(c not in contenedor for c in CAMPOS_FIRMA):
        raise ErrorFirma("El archivo no está firmado: no se permite descifrarlo.")

    signer_id = contenedor["signer_id"]
    if isinstance(signer_id, str):
        for usuario in listar_identidades(carpeta_base):
            try:
                publica = cargar_identidad_publica(
                    Path(carpeta_base) / usuario, gestor_claves
                )
            except (FileNotFoundError, DirectorioAlterado):
                continue
            if hmac.compare_digest(publica["signer_id"].encode(), signer_id.encode()):
                return publica

    raise ErrorFirma(
        "Remitente desconocido: la firma no corresponde a ninguna identidad del directorio."
    )


def recibir_archivo(
    ruta_vault,
    ruta_salida,
    id_usuario,
    carpeta_destinatario,
    password_destinatario,
    clave_publica_remitente,
    gestor_claves,
):
    """Verifica firma y estado de las claves antes de recuperar el archivo."""
    if gestor_claves is None:
        raise ValueError("Se requiere un gestor de claves para validar la revocación.")

    identidad = recuperar_identidad(password_destinatario, carpeta_destinatario)

    return abrir_archivo_firmado(
        ruta_vault,
        identidad["clave_ecies"],
        id_usuario,
        clave_publica_remitente,
        gestor_claves,
        ruta_salida=ruta_salida,
    )


# --------------------------------------------------------------------------
# Revocación
# --------------------------------------------------------------------------
def revocar_identidad(usuario, carpeta, gestor_claves, motivo):
    """Revoca la identidad de forma persistente y la retira del repositorio.

    Orden (falla cerrado):
      1. Registrar la revocación en disco (historial cifrado, fsync): quedan
         revocadas la huella ECIES y la huella de la llave de firma.
      2. Eliminar ecies.keystore y firma.keystore del repositorio de llaves.
    Si el paso 2 fallara, la identidad ya está revocada y su uso bloqueado.
    El directorio público se conserva: sirve para mostrar que está revocada.

    Devuelve True si se eliminó algún keystore. Los respaldos (key_backup)
    son copias aparte; aun así una clave revocada no puede re-registrarse.
    """
    gestor_claves.revocar_clave(usuario, motivo)
    carpeta = Path(carpeta)
    eliminadas = [eliminar_keystore(carpeta / a) for a in (ARCHIVO_ECIES, ARCHIVO_FIRMA)]
    return any(eliminadas)


"""Integración D2 + D3 + D5 + D6 del Secure Digital Document Vault."""

from pathlib import Path

from cryptography.hazmat.primitives import serialization

from vault.keystore import (
    cargar_keystore,
    guardar_keystore,
    proteger_clave_privada,
    recuperar_clave_privada,
)
from vault.public_key import (
    generar_par_claves,
    validar_clave_publica,
)
from vault.signed_sharing import (
    abrir_archivo_firmado,
    firmar_y_compartir_archivo,
)
from vault.signatures import (
    generar_par_claves_firma,
    huella_clave_firma,
)


def _serializar_privada(clave):
    """Serialización PKCS#8; el keystore aporta el cifrado."""
    return clave.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _recuperar_privada(ruta_keystore, password, tipo):
    almacen = cargar_keystore(ruta_keystore)
    datos = recuperar_clave_privada(almacen, password)

    clave = serialization.load_der_private_key(
        datos,
        password=None,
    )

    if tipo == "ecies":
        from cryptography.hazmat.primitives.asymmetric import ec

        if not isinstance(clave, ec.EllipticCurvePrivateKey):
            raise ValueError("La clave recuperada no es ECIES.")

        validar_clave_publica(clave.public_key())

    elif tipo == "firma":
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        if not isinstance(clave, Ed25519PrivateKey):
            raise ValueError("La clave recuperada no es Ed25519.")

    else:
        raise ValueError("Tipo de clave no admitido.")

    return clave


def crear_identidad(usuario, password, carpeta):
    """Genera y protege las claves ECIES y Ed25519 del usuario."""
    if not isinstance(usuario, str) or not usuario.strip():
        raise ValueError("Usuario inválido.")

    carpeta = Path(carpeta)
    carpeta.mkdir(parents=True, exist_ok=True)

    ruta_ecies = carpeta / "ecies.keystore"
    ruta_firma = carpeta / "firma.keystore"

    if ruta_ecies.exists() or ruta_firma.exists():
        raise FileExistsError("La identidad ya tiene archivos de claves.")

    clave_ecies = generar_par_claves()
    clave_firma = generar_par_claves_firma()

    almacen_ecies = proteger_clave_privada(
        _serializar_privada(clave_ecies),
        password,
        f"{usuario}:ecies",
    )

    almacen_firma = proteger_clave_privada(
        _serializar_privada(clave_firma),
        password,
        f"{usuario}:firma",
    )

    guardar_keystore(ruta_ecies, almacen_ecies)
    guardar_keystore(ruta_firma, almacen_firma)

    return {
        "usuario": usuario,
        "clave_publica_ecies": clave_ecies.public_key(),
        "clave_publica_firma": clave_firma.public_key(),
        "signer_id": huella_clave_firma(clave_firma.public_key()),
    }


def recuperar_identidad(password, carpeta):
    """Recupera las dos claves privadas protegidas."""
    carpeta = Path(carpeta)

    return {
        "clave_ecies": _recuperar_privada(
            carpeta / "ecies.keystore", password, "ecies"
        ),
        "clave_firma": _recuperar_privada(
            carpeta / "firma.keystore", password, "firma"
        ),
    }


def enviar_archivo(
    ruta_origen,
    ruta_vault,
    destinatarios,
    carpeta_remitente,
    password_remitente,
):
    """Cifra para destinatarios y firma con la identidad del remitente."""
    identidad = recuperar_identidad(
        password_remitente,
        carpeta_remitente,
    )

    firmar_y_compartir_archivo(
        ruta_origen,
        ruta_vault,
        destinatarios,
        identidad["clave_firma"],
    )

    return Path(ruta_vault)


def recibir_archivo(
    ruta_vault,
    ruta_salida,
    id_usuario,
    carpeta_destinatario,
    password_destinatario,
    clave_publica_remitente,
    gestor_claves,
):
    """Verifica firma y estado de clave antes de recuperar el archivo."""
    if gestor_claves is None:
        raise ValueError(
            "Se requiere un gestor de claves para validar la revocación."
        )

    identidad = recuperar_identidad(
        password_destinatario,
        carpeta_destinatario,
    )

    return abrir_archivo_firmado(
        ruta_vault,
        identidad["clave_ecies"],
        id_usuario,
        clave_publica_remitente,
        ruta_salida=ruta_salida,
        gestor_claves=gestor_claves,
    )


def registrar_identidad_en_gestor(
    usuario,
    carpeta,
    password,
    gestor_claves,
):
    """Registra una identidad recuperada desde el keystore."""
    identidad = recuperar_identidad(password, carpeta)

    return gestor_claves.registrar_clave_existente(
        usuario,
        identidad["clave_ecies"],
    )


    with gestor_claves._lock:
        if usuario in gestor_claves._registros:
            raise ValueError("El usuario ya tiene una identidad registrada.")

        fingerprint = gestor_claves._fingerprint(clave.public_key())

        registro = RegistroClave(
            usuario=usuario,
            fingerprint=fingerprint,
            version=1,
            creada=datetime.now(timezone.utc).isoformat(),
        )

        gestor_claves._registros[usuario] = registro
        gestor_claves._claves_activas[usuario] = clave
        gestor_claves._versiones[usuario] = 1
        gestor_claves._guardar_estado()

    return registro

def enviar_archivo_verificado(
    ruta_origen,
    ruta_vault,
    destinatarios,
    huellas_confiables,
    carpeta_remitente,
    password_remitente,
):
    """Verifica las identidades antes de cifrar y firmar."""
    from vault.public_key import verificar_huella

    if not destinatarios:
        raise ValueError("Debe existir al menos un destinatario.")

    if set(destinatarios) != set(huellas_confiables):
        raise ValueError(
            "Cada destinatario debe tener una huella confiable."
        )

    for usuario, clave_publica in destinatarios.items():
        verificar_huella(
            clave_publica,
            huellas_confiables[usuario],
        )

    return enviar_archivo(
        ruta_origen,
        ruta_vault,
        destinatarios,
        carpeta_remitente,
        password_remitente,
    )

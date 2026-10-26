from pathlib import Path

from vault.decryption import descifrar_archivo
from vault.encryption import cifrar_archivo
from vault.key_management import generar_clave_archivo, generar_nonce
from vault.public_key import (
    DestinatarioNoAutorizado,
    ErrorDeAcceso,
    crear_etiqueta_envoltura,
    desenvolver_clave,
    envolver_clave,
    huella_clave_publica,
    validar_clave_publica,
)
from vault.shared_container import (
    TAMANO_TAG,
    a_base64,
    clave_unicidad_id,
    construir_aad,
    crear_encabezado,
    desde_base64,
    guardar_contenedor_compartido,
    leer_contenedor_compartido,
    validar_contenedor,
    validar_id_destinatario,
)

__all__ = [
    "ErrorDeAcceso",
    "DestinatarioNoAutorizado",
    "cifrar_para_destinatarios",
    "descifrar_como_destinatario",
    "compartir_archivo",
    "abrir_archivo_compartido",
]


def cifrar_para_destinatarios(
    datos: bytes,
    nombre_archivo: str,
    destinatarios: dict,
) -> dict:
    """
    Cifra `datos` una sola vez y los comparte con varios destinatarios.

    destinatarios: {id_usuario: clave_publica_RSA}

    Devuelve el contenedor (diccionario JSON-serializable).
    """
    if not destinatarios:
        raise ValueError("Se necesita al menos un destinatario.")

    encabezado = crear_encabezado(nombre_archivo)

    clave_archivo = generar_clave_archivo()
    nonce = generar_nonce()

    entradas = []
    huellas = set()
    ids = set()

    for id_destinatario, clave_publica in destinatarios.items():
        validar_id_destinatario(id_destinatario)
        validar_clave_publica(clave_publica)

        if clave_unicidad_id(id_destinatario) in ids:
            raise ValueError("Identificadores de usuario duplicados.")

        ids.add(clave_unicidad_id(id_destinatario))

        huella = huella_clave_publica(clave_publica)

        if huella in huellas:
            raise ValueError(
                "Dos destinatarios comparten la misma clave pública."
            )

        huellas.add(huella)

        etiqueta = crear_etiqueta_envoltura(
            encabezado["id_archivo"],
            huella,
            id_destinatario,
        )

        entradas.append(
            {
                "id": id_destinatario,
                "key_id": huella,
                "encrypted_key": a_base64(
                    envolver_clave(clave_archivo, clave_publica, etiqueta)
                ),
            }
        )

    aad = construir_aad(encabezado, entradas)

    cifrado = cifrar_archivo(datos, clave_archivo, nonce, aad)

    # AESGCM devuelve ciphertext || tag; se guardan por separado
    ciphertext = cifrado[:-TAMANO_TAG]
    tag = cifrado[-TAMANO_TAG:]

    contenedor = {
        "header": encabezado,
        "recipients": entradas,
        "nonce": a_base64(nonce),
        "ciphertext": a_base64(ciphertext),
        "tag": a_base64(tag),
    }

    validar_contenedor(contenedor)
    return contenedor


def _buscar_entrada(contenedor: dict, huella: str) -> dict:
    """
    Búsqueda determinista por key_id. validar_contenedor garantiza que
    no hay key_ids repetidos, así que hay como máximo una coincidencia.
    """
    for entrada in contenedor["recipients"]:
        if entrada["key_id"] == huella:
            return entrada

    raise DestinatarioNoAutorizado(
        "Esta clave no corresponde a ningún destinatario del archivo."
    )


def descifrar_como_destinatario(
    contenedor,
    clave_privada,
    id_usuario: str = None,
) -> bytes:
    """
    Descifra un contenedor compartido usando la clave privada de un
    destinatario.

    contenedor: diccionario o ruta a un archivo .vault.
    id_usuario: si se indica, la entrada encontrada debe pertenecer a
                ese usuario (protege contra suplantación de identidad).

    Errores:
      DestinatarioNoAutorizado: la clave no está en la lista.
      ErrorDeAcceso: la clave envuelta no se pudo recuperar.
      cryptography.exceptions.InvalidTag: el contenido, el encabezado o la
        lista de destinatarios fueron modificados.
      ContenedorInvalido (ValueError): formato inválido.
    """
    if isinstance(contenedor, (str, Path)):
        contenedor = leer_contenedor_compartido(contenedor)
    else:
        validar_contenedor(contenedor)

    # El key_id se calcula desde la clave privada presentada: no se
    # confía en ningún identificador que declare el propio usuario.
    huella = huella_clave_publica(clave_privada.public_key())

    entrada = _buscar_entrada(contenedor, huella)

    if id_usuario is not None and entrada["id"] != id_usuario:
        raise DestinatarioNoAutorizado(
            "La clave presentada no pertenece al usuario indicado."
        )

    encabezado = contenedor["header"]

    etiqueta = crear_etiqueta_envoltura(
        encabezado["id_archivo"],
        entrada["key_id"],
        entrada["id"],
    )

    clave_archivo = desenvolver_clave(
        desde_base64(entrada["encrypted_key"]),
        clave_privada,
        etiqueta,
    )

    aad = construir_aad(encabezado, contenedor["recipients"])

    datos_cifrados = (
        desde_base64(contenedor["ciphertext"])
        + desde_base64(contenedor["tag"])
    )

    return descifrar_archivo(
        datos_cifrados,
        clave_archivo,
        desde_base64(contenedor["nonce"]),
        aad,
    )


# Operaciones sobre archivos en disco

def compartir_archivo(ruta_origen, ruta_vault, destinatarios: dict) -> None:
    """Lee un archivo, lo cifra para los destinatarios y guarda el .vault."""
    origen = Path(ruta_origen)

    contenedor = cifrar_para_destinatarios(
        origen.read_bytes(),
        origen.name,
        destinatarios,
    )

    guardar_contenedor_compartido(contenedor, ruta_vault)


def abrir_archivo_compartido(
    ruta_vault,
    clave_privada,
    id_usuario: str = None,
    ruta_salida=None,
) -> bytes:
    """
    Descifra un .vault como destinatario. Si se da ruta_salida, además
    escribe el archivo recuperado.
    """
    datos = descifrar_como_destinatario(
        ruta_vault,
        clave_privada,
        id_usuario,
    )

    if ruta_salida is not None:
        Path(ruta_salida).write_bytes(datos)

    return datos
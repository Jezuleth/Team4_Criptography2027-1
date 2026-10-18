import json

import pytest
from cryptography.exceptions import InvalidTag

from vault.encryption import cifrar_con_contraseña
from vault.decryption import (
    descifrar_archivo,
    descifrar_con_contraseña,
    descifrar_contenedor
)
from vault.key_management import recuperar_clave
from vault.container import (
    crear_metadatos,
    serializar_metadatos,
    crear_contenedor,
    guardar_contenedor
)


def preparar_datos():
    datos = b"Archivo secreto del D2"
    contraseña = "MiClave123"

    metadatos = crear_metadatos("documento.txt")
    aad = serializar_metadatos(metadatos)

    resultado = cifrar_con_contraseña(
        datos,
        contraseña,
        aad
    )

    return datos, contraseña, metadatos, aad, resultado


def test_descifrado_correcto():
    datos, contraseña, _, aad, resultado = preparar_datos()

    recuperados = descifrar_con_contraseña(
        resultado,
        contraseña,
        aad
    )

    assert recuperados == datos


def test_descifrado_clave_incorrecta():
    datos, contraseña, _, aad, resultado = preparar_datos()

    clave = recuperar_clave(
        resultado["clave_protegida"],
        contraseña
    )

    clave_incorrecta = bytes(32)

    with pytest.raises(InvalidTag):
        descifrar_archivo(
            resultado["datos_cifrados"],
            clave_incorrecta,
            resultado["nonce"],
            aad
        )


def test_descifrado_contraseña_incorrecta():
    _, _, _, aad, resultado = preparar_datos()

    with pytest.raises(InvalidTag):
        descifrar_con_contraseña(
            resultado,
            "ContraseñaIncorrecta",
            aad
        )


def test_detectar_contenido_modificado():
    _, contraseña, _, aad, resultado = preparar_datos()

    datos_modificados = bytearray(
        resultado["datos_cifrados"]
    )
    datos_modificados[0] ^= 1

    resultado["datos_cifrados"] = bytes(datos_modificados)

    with pytest.raises(InvalidTag):
        descifrar_con_contraseña(
            resultado,
            contraseña,
            aad
        )


def test_detectar_metadatos_modificados():
    _, contraseña, _, _, resultado = preparar_datos()

    aad_modificado = b"nombre=archivo_modificado.txt"

    with pytest.raises(InvalidTag):
        descifrar_con_contraseña(
            resultado,
            contraseña,
            aad_modificado
        )


def test_descifrar_contenedor_completo(tmp_path):
    datos, contraseña, metadatos, _, resultado = preparar_datos()

    contenedor = crear_contenedor(
        metadatos,
        resultado
    )

    ruta = tmp_path / "documento.vault"

    guardar_contenedor(contenedor, ruta)

    recuperados = descifrar_contenedor(
        ruta,
        contraseña
    )

    assert recuperados == datos


def test_contenedor_modificado(tmp_path):
    datos, contraseña, metadatos, _, resultado = preparar_datos()

    contenedor = crear_contenedor(
        metadatos,
        resultado
    )

    ruta = tmp_path / "documento.vault"
    guardar_contenedor(contenedor, ruta)

    contenido = json.loads(
        ruta.read_text(encoding="utf-8")
    )

    contenido["header"]["nombre_archivo"] = "alterado.txt"

    ruta.write_text(
        json.dumps(contenido),
        encoding="utf-8"
    )

    with pytest.raises(InvalidTag):
        descifrar_contenedor(
            ruta,
            contraseña
        )
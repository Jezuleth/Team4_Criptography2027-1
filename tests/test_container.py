
import json

import pytest
from cryptography.exceptions import InvalidTag

from vault.container import (
    crear_metadatos,
    serializar_metadatos,
    crear_contenedor,
    guardar_contenedor,
    leer_contenedor,
)
from vault.encryption import cifrar_con_contraseña
from vault.key_management import recuperar_clave
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def preparar_contenedor(tmp_path):
    metadatos = crear_metadatos("documento.txt")
    aad = serializar_metadatos(metadatos)

    resultado = cifrar_con_contraseña(
        b"Archivo confidencial",
        "MiContrasenaSegura",
        aad,
    )

    contenedor = crear_contenedor(metadatos, resultado)
    ruta = tmp_path / "documento.vault"
    guardar_contenedor(contenedor, ruta)

    return ruta


def test_crear_metadatos():
    metadatos = crear_metadatos("documento.txt")

    assert metadatos["nombre_archivo"] == "documento.txt"
    assert metadatos["algoritmo"] == "AES-256-GCM"
    assert metadatos["version"] == 1
    assert "fecha" in metadatos


def test_nombre_vacio():
    with pytest.raises(ValueError):
        crear_metadatos("")


def test_serializacion_consistente():
    metadatos = {"version": 1, "nombre_archivo": "archivo.txt"}

    assert serializar_metadatos(metadatos) == serializar_metadatos(
        {"nombre_archivo": "archivo.txt", "version": 1}
    )


def test_guardar_y_leer_contenedor(tmp_path):
    ruta = preparar_contenedor(tmp_path)
    contenedor = leer_contenedor(ruta)

    assert contenedor["metadatos"]["nombre_archivo"] == "documento.txt"
    assert len(contenedor["nonce"]) == 12
    assert len(contenedor["datos_cifrados"]) >= 16


def test_descifrado_desde_contenedor(tmp_path):
    ruta = preparar_contenedor(tmp_path)
    contenedor = leer_contenedor(ruta)

    clave = recuperar_clave(
        contenedor["clave_protegida"],
        "MiContrasenaSegura",
    )

    aad = serializar_metadatos(contenedor["metadatos"])

    datos = AESGCM(clave).decrypt(
        contenedor["nonce"],
        contenedor["datos_cifrados"],
        aad,
    )

    assert datos == b"Archivo confidencial"


def test_detectar_metadatos_modificados(tmp_path):
    ruta = preparar_contenedor(tmp_path)

    contenedor = json.loads(ruta.read_text(encoding="utf-8"))
    contenedor["header"]["nombre_archivo"] = "modificado.txt"
    ruta.write_text(json.dumps(contenedor), encoding="utf-8")

    resultado = leer_contenedor(ruta)
    clave = recuperar_clave(
        resultado["clave_protegida"],
        "MiContrasenaSegura",
    )

    with pytest.raises(InvalidTag):
        AESGCM(clave).decrypt(
            resultado["nonce"],
            resultado["datos_cifrados"],
            serializar_metadatos(resultado["metadatos"]),
        )


def test_json_invalido(tmp_path):
    ruta = tmp_path / "invalido.vault"
    ruta.write_text("{json incorrecto", encoding="utf-8")

    with pytest.raises(json.JSONDecodeError):
        leer_contenedor(ruta)


def test_nonce_invalido(tmp_path):
    ruta = preparar_contenedor(tmp_path)

    contenedor = json.loads(ruta.read_text(encoding="utf-8"))
    contenedor["nonce"] = "YWJj"
    ruta.write_text(json.dumps(contenedor), encoding="utf-8")

    with pytest.raises(ValueError):
        leer_contenedor(ruta)

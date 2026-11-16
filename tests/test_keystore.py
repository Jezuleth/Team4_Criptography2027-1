
"""D6: pruebas de seguridad del keystore cifrado."""

import copy
import os

import pytest

from vault.keystore import (
    ErrorKeystore,
    proteger_clave_privada,
    recuperar_clave_privada,
    guardar_keystore,
    cargar_keystore,
)


@pytest.fixture
def datos_clave():
    return {
        "privada": os.urandom(32),
        "password": "PasswordSeguro123!",
        "key_id": "alice-firma-v1",
    }


@pytest.fixture
def almacen(datos_clave):
    return proteger_clave_privada(
        datos_clave["privada"],
        datos_clave["password"],
        datos_clave["key_id"],
    )


def test_cifrado_y_recuperacion(datos_clave, almacen):
    recuperada = recuperar_clave_privada(
        almacen, datos_clave["password"]
    )
    assert recuperada == datos_clave["privada"]


def test_no_guarda_clave_en_texto_plano(datos_clave, almacen):
    import base64

    cifrado = base64.b64decode(almacen["ciphertext"])
    assert cifrado != datos_clave["privada"]


def test_password_incorrecto(almacen):
    with pytest.raises(ErrorKeystore):
        recuperar_clave_privada(almacen, "incorrecta")


@pytest.mark.parametrize(
    "campo",
    ["ciphertext", "salt", "nonce", "key_id"],
)
def test_manipulacion_detectada(almacen, campo):
    alterado = copy.deepcopy(almacen)

    if campo == "key_id":
        alterado[campo] = "mallory-firma-v1"
    else:
        alterado[campo] = "AAAA"

    with pytest.raises(ErrorKeystore):
        recuperar_clave_privada(
            alterado, "PasswordSeguro123!"
        )


def test_salt_y_nonce_aleatorios(datos_clave):
    primero = proteger_clave_privada(
        datos_clave["privada"],
        datos_clave["password"],
        datos_clave["key_id"],
    )
    segundo = proteger_clave_privada(
        datos_clave["privada"],
        datos_clave["password"],
        datos_clave["key_id"],
    )

    assert primero["salt"] != segundo["salt"]
    assert primero["nonce"] != segundo["nonce"]
    assert primero["ciphertext"] != segundo["ciphertext"]


def test_guardar_y_cargar_keystore(tmp_path, almacen):
    ruta = tmp_path / "alice.keystore"

    guardar_keystore(ruta, almacen)
    cargado = cargar_keystore(ruta)

    assert cargado == almacen
    assert recuperar_clave_privada(
        cargado, "PasswordSeguro123!"
    ) is not None


def test_no_sobrescribir_keystore(tmp_path, almacen):
    ruta = tmp_path / "alice.keystore"

    guardar_keystore(ruta, almacen)
    contenido_original = ruta.read_bytes()

    with pytest.raises(FileExistsError):
        guardar_keystore(ruta, almacen)

    assert ruta.read_bytes() == contenido_original


def test_archivo_inexistente(tmp_path):
    ruta = tmp_path / "no_existe.keystore"

    with pytest.raises(ErrorKeystore):
        cargar_keystore(ruta)


def test_clave_privada_invalida():
    with pytest.raises(ErrorKeystore):
        proteger_clave_privada(
            b"", "PasswordSeguro123!", "alice"
        )


def test_password_vacio(datos_clave):
    with pytest.raises(ErrorKeystore):
        proteger_clave_privada(
            datos_clave["privada"], "", datos_clave["key_id"]
        )


def test_formato_no_compatible(almacen):
    alterado = copy.deepcopy(almacen)
    alterado["version"] = 99

    with pytest.raises(ErrorKeystore):
        recuperar_clave_privada(
            alterado, "PasswordSeguro123!"
        )

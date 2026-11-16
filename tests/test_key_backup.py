
"""D6: pruebas de respaldo, recuperación e integración."""

import pytest

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vault.key_backup import (
    ErrorBackup,
    crear_backup,
    restaurar_backup,
    verificar_backup,
)
from vault.key_lifecycle import GestorCicloVida
from vault.keystore import (
    proteger_clave_privada,
    recuperar_clave_privada,
    guardar_keystore,
    cargar_keystore,
)


def abrir_identidad(ruta, password):
    """Recupera una clave privada desde un keystore cifrado."""
    almacen = cargar_keystore(ruta)
    datos = recuperar_clave_privada(almacen, password)
    return serialization.load_der_private_key(datos, password=None)


@pytest.fixture
def identidad(tmp_path):
    ruta = tmp_path / "alice.keystore"
    password = "PasswordSeguro123!"

    gestor = GestorCicloVida()
    privada, registro = gestor.generar_clave("alice")

    datos = privada.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    almacen = proteger_clave_privada(
        datos, password, registro.fingerprint
    )
    guardar_keystore(ruta, almacen)

    return ruta, password


def test_crear_backup(identidad, tmp_path):
    origen, password = identidad
    backup = tmp_path / "alice.backup"

    crear_backup(origen, backup, password)

    assert backup.exists()
    assert verificar_backup(backup, password)


def test_restaurar_backup(identidad, tmp_path):
    origen, password = identidad
    backup = tmp_path / "alice.backup"
    restaurado = tmp_path / "alice_restaurada.keystore"

    crear_backup(origen, backup, password)
    restaurar_backup(backup, restaurado, password)

    assert restaurado.exists()

    privada_original = abrir_identidad(origen, password)
    privada_restaurada = abrir_identidad(restaurado, password)

    assert (
        privada_original.public_key().public_numbers()
        == privada_restaurada.public_key().public_numbers()
    )


def test_password_incorrecto(identidad, tmp_path):
    origen, _ = identidad
    backup = tmp_path / "alice.backup"

    with pytest.raises(ErrorBackup):
        crear_backup(origen, backup, "incorrecta")

    assert not backup.exists()


def test_backup_alterado(identidad, tmp_path):
    origen, password = identidad
    backup = tmp_path / "alice.backup"

    crear_backup(origen, backup, password)

    datos = bytearray(backup.read_bytes())
    datos[-5] ^= 1
    backup.write_bytes(datos)

    assert not verificar_backup(backup, password)


def test_no_sobrescribir_identidad(identidad, tmp_path):
    origen, password = identidad
    backup = tmp_path / "alice.backup"

    crear_backup(origen, backup, password)

    with pytest.raises(ErrorBackup):
        restaurar_backup(backup, origen, password)


def test_integracion_firma_despues_de_restaurar(
    identidad, tmp_path
):
    origen, password = identidad
    backup = tmp_path / "alice.backup"
    restaurado = tmp_path / "alice_restaurada.keystore"

    crear_backup(origen, backup, password)
    restaurar_backup(backup, restaurado, password)

    privada = abrir_identidad(restaurado, password)

    mensaje = b"Documento protegido D5-D6"
    firma = privada.sign(mensaje, ec.ECDSA(hashes.SHA256()))

    privada.public_key().verify(
        firma, mensaje, ec.ECDSA(hashes.SHA256())
    )


def test_restauracion_rechaza_password_incorrecto(
    identidad, tmp_path
):
    origen, password = identidad
    backup = tmp_path / "alice.backup"
    destino = tmp_path / "restaurada.keystore"

    crear_backup(origen, backup, password)

    with pytest.raises(ErrorBackup):
        restaurar_backup(backup, destino, "incorrecta")

    assert not destino.exists()


import pytest

from vault.key_management import (
    generar_clave_archivo,
    generar_nonce,
    generar_salt,
    derivar_clave,
    proteger_clave,
)


def test_generar_clave_archivo():
    clave1 = generar_clave_archivo()
    clave2 = generar_clave_archivo()

    assert len(clave1) == 32
    assert clave1 != clave2


def test_generar_nonce():
    assert len(generar_nonce()) == 12


def test_generar_salt():
    assert len(generar_salt()) == 16


def test_derivar_clave():
    salt = generar_salt()

    clave1 = derivar_clave("Password123!", salt)
    clave2 = derivar_clave("Password123!", salt)

    assert len(clave1) == 32
    assert clave1 == clave2


def test_contraseña_vacia():
    with pytest.raises(ValueError):
        derivar_clave("", generar_salt())


def test_proteger_clave():
    clave = generar_clave_archivo()
    resultado = proteger_clave(clave, "Password123!")

    assert len(resultado["salt"]) == 16
    assert len(resultado["nonce"]) == 12
    assert len(resultado["clave_cifrada"]) == 48
    assert resultado["clave_cifrada"] != clave

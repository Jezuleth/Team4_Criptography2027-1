
import pytest

from vault.key_lifecycle import (
    GestorCicloVida,
    ErrorCicloVida,
)


def test_generar_clave():
    gestor = GestorCicloVida()

    clave, registro = gestor.generar_clave("alice")

    assert clave is not None
    assert registro.usuario == "alice"
    assert registro.estado == "activa"


def test_obtener_clave():
    gestor = GestorCicloVida()
    gestor.generar_clave("alice")

    clave = gestor.obtener_clave("alice")

    assert clave is not None


def test_rotar_clave():
    gestor = GestorCicloVida()

    clave1, registro1 = gestor.generar_clave("alice")
    clave2, registro2 = gestor.rotar_clave("alice")

    assert registro1.estado == "rotada"
    assert registro2.version == 2
    assert clave1 != clave2


def test_revocar_clave():
    gestor = GestorCicloVida()
    gestor.generar_clave("alice")

    gestor.revocar_clave("alice", "Sospecha de compromiso")

    with pytest.raises(ErrorCicloVida):
        gestor.obtener_clave("alice")


def test_usuario_inexistente():
    gestor = GestorCicloVida()

    with pytest.raises(ErrorCicloVida):
        gestor.obtener_clave("desconocido")


def test_descargar_clave():
    gestor = GestorCicloVida()
    gestor.generar_clave("alice")

    gestor.descargar_clave_de_memoria("alice")

    with pytest.raises(ErrorCicloVida):
        gestor.obtener_clave("alice")


def test_fingerprint_cambia_al_rotar():
    gestor = GestorCicloVida()

    _, registro1 = gestor.generar_clave("alice")
    _, registro2 = gestor.rotar_clave("alice")

    assert registro1.fingerprint != registro2.fingerprint
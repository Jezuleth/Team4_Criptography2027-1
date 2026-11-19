
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

def test_revocacion_persiste_tras_reinicio(tmp_path):
    ruta = tmp_path / "estado_claves.json"
    password = "PasswordSegura123!"

    gestor = GestorCicloVida(
        ruta_estado=ruta,
        password_estado=password,
    )

    _, registro = gestor.generar_clave("alice")
    gestor.revocar_clave("alice", "Clave comprometida")

    # Simulamos reiniciar la aplicación
    nuevo_gestor = GestorCicloVida(
        ruta_estado=ruta,
        password_estado=password,
    )

    registro_recuperado = nuevo_gestor.obtener_registro("alice")

    assert registro_recuperado.estado == "revocada"
    assert registro_recuperado.version == registro.version
    assert registro_recuperado.motivo_revocacion == "Clave comprometida"

    with pytest.raises(ErrorCicloVida):
        nuevo_gestor.obtener_clave("alice")

def test_rotacion_persiste_tras_reinicio(tmp_path):
    ruta = tmp_path / "estado_claves.json"
    password = "PasswordSegura123!"

    gestor = GestorCicloVida(
        ruta_estado=ruta,
        password_estado=password,
    )

    _, registro1 = gestor.generar_clave("alice")
    _, registro2 = gestor.rotar_clave("alice")

    nuevo_gestor = GestorCicloVida(
        ruta_estado=ruta,
        password_estado=password,
    )

    recuperado = nuevo_gestor.obtener_registro("alice")

    assert recuperado.version == 2
    assert recuperado.fingerprint == registro2.fingerprint
    assert recuperado.fingerprint != registro1.fingerprint

    # La clave privada no se recupera automáticamente.
    with pytest.raises(ErrorCicloVida):
        nuevo_gestor.obtener_clave("alice")

def test_manipulacion_historial_detectada(tmp_path):
    import json

    ruta = tmp_path / "estado_claves.json"
    password = "PasswordSegura123!"

    gestor = GestorCicloVida(
        ruta_estado=ruta,
        password_estado=password,
    )

    gestor.generar_clave("alice")

    contenido = json.loads(ruta.read_text(encoding="utf-8"))

    # Alteramos el contenido cifrado.
    cifrado = contenido["ciphertext"]
    contenido["ciphertext"] = (
        ("A" if cifrado[0] != "A" else "B") + cifrado[1:]
    )

    ruta.write_text(
        json.dumps(contenido),
        encoding="utf-8",
    )

    # El gestor debe rechazar el historial manipulado.
    with pytest.raises(ErrorCicloVida):
        GestorCicloVida(
            ruta_estado=ruta,
            password_estado=password,
        )
def test_clave_revocada_no_autorizada_para_uso():
    gestor = GestorCicloVida()

    clave, _ = gestor.generar_clave("alice")

    assert gestor.validar_clave_para_uso(
        "alice", clave
    ) is True

    gestor.revocar_clave(
        "alice", "Clave comprometida"
    )

    with pytest.raises(ErrorCicloVida):
        gestor.validar_clave_para_uso(
            "alice", clave
        )

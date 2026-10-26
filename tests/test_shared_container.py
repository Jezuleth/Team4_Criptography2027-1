import base64
import copy

import pytest

from vault.shared_container import (
    ContenedorInvalido,
    construir_aad,
    crear_encabezado,
    guardar_contenedor_compartido,
    leer_contenedor_compartido,
    validar_contenedor,
    validar_id_destinatario,
)


def test_estructura_del_contenedor(contenedor):
    assert set(contenedor) == {"header", "recipients", "nonce", "ciphertext", "tag"}
    assert [r["id"] for r in contenedor["recipients"]] == ["alice", "bob"]

    for entrada in contenedor["recipients"]:
        assert set(entrada) == {"id", "key_id", "encrypted_key"}


def test_encabezado_incluye_identificadores_de_algoritmo(contenedor):
    encabezado = contenedor["header"]

    assert encabezado["version"] == 2
    assert encabezado["algoritmo"] == "AES-256-GCM"
    assert encabezado["algoritmo_envoltura"] == "RSA-OAEP-SHA256"
    assert encabezado["algoritmo_huella"] == "SHA256-SPKI-DER"


def test_encabezado_nombre_obligatorio():
    with pytest.raises(ValueError):
        crear_encabezado("")


def test_guardar_y_leer(tmp_path, contenedor):
    ruta = tmp_path / "doc.vault"

    guardar_contenedor_compartido(contenedor, ruta)

    assert leer_contenedor_compartido(ruta) == contenedor


def test_aad_es_determinista_y_depende_de_los_destinatarios(contenedor):
    encabezado = contenedor["header"]
    destinatarios = contenedor["recipients"]

    assert construir_aad(encabezado, destinatarios) == construir_aad(
        copy.deepcopy(encabezado), copy.deepcopy(destinatarios)
    )

    # El orden de los destinatarios también queda autenticado
    assert construir_aad(encabezado, destinatarios) != construir_aad(
        encabezado, list(reversed(destinatarios))
    )

    # Quitar un destinatario cambia el AAD
    assert construir_aad(encabezado, destinatarios) != construir_aad(
        encabezado, destinatarios[:1]
    )


def _modificar(contenedor, cambio):
    copia = copy.deepcopy(contenedor)
    cambio(copia)
    return copia


@pytest.mark.parametrize(
    "cambio",
    [
        lambda c: c.update(extra="no autenticado"),
        lambda c: c.pop("tag"),
        lambda c: c["header"].update(extra=1),
        lambda c: c["header"].update(version=1),
        lambda c: c["header"].update(algoritmo="AES-128-GCM"),
        lambda c: c["header"].update(algoritmo_envoltura="RSA-PKCS1v15"),
        lambda c: c["header"].update(algoritmo_huella="MD5"),
        lambda c: c["header"].update(id_archivo="AAAA"),
        lambda c: c.update(recipients=[]),
        lambda c: c.update(recipients="alice"),
        lambda c: c["recipients"][0].update(extra="x"),
        lambda c: c["recipients"][0].pop("key_id"),
        lambda c: c["recipients"][0].update(key_id="no-es-una-huella"),
        lambda c: c["recipients"][0].update(key_id="A" * 64),
        lambda c: c["recipients"][0].update(encrypted_key="@@@no-base64@@@"),
        lambda c: c["recipients"][0].update(encrypted_key="AAAA"),
        lambda c: c["recipients"][1].update(id="alice"),
        lambda c: c["recipients"][1].update(key_id=c["recipients"][0]["key_id"]),
        lambda c: c["recipients"][0].update(id=""),
        lambda c: c.update(nonce="AAAA"),
        lambda c: c.update(tag="AAAA"),
        lambda c: c.update(ciphertext="!!!"),
    ],
)
def test_contenedor_mal_formado_es_rechazado(contenedor, cambio):
    with pytest.raises(ContenedorInvalido):
        validar_contenedor(_modificar(contenedor, cambio))


def test_json_con_campos_duplicados_es_rechazado(tmp_path, contenedor):
    ruta = tmp_path / "duplicado.vault"
    guardar_contenedor_compartido(contenedor, ruta)

    texto = ruta.read_text(encoding="utf-8")
    texto = texto.replace('"nonce"', '"nonce": "AAAA", "nonce"', 1)
    ruta.write_text(texto, encoding="utf-8")

    with pytest.raises(ContenedorInvalido):
        leer_contenedor_compartido(ruta)


@pytest.mark.parametrize(
    "contenido_roto",
    [
        b"{no es json",
        b"\xff\xfe\x00 no es utf-8",
        b"[" * 100000,
        b'{"header": "\\ud800"}',
        b"[]",
        b"",
    ],
    ids=["json_roto", "no_utf8", "anidado_profundo", "surrogate_invalido", "lista", "vacio"],
)
def test_archivo_ilegible_siempre_es_contenedor_invalido(tmp_path, contenido_roto):
    """Todos los fallos de lectura se reportan con un único tipo de error."""
    ruta = tmp_path / "roto.vault"
    ruta.write_bytes(contenido_roto)

    with pytest.raises(ContenedorInvalido):
        leer_contenedor_compartido(ruta)


@pytest.mark.parametrize(
    "id_invalido",
    [
        "",
        "   ",
        None,
        7,
        "a" * 129,
        "al\nice",
        " alice",
        "alice ",
        "alice​",      # espacio de ancho cero (formato)
        "alice‮",      # override de derecha a izquierda
        "ali\x7fce",        # control
        "élisa",      # NFD, no NFC
        "ali\ud800ce",      # sustituto suelto
    ],
)
def test_ids_de_usuario_invalidos(id_invalido):
    with pytest.raises(ValueError):
        validar_id_destinatario(id_invalido)


@pytest.mark.parametrize("id_valido", ["alice", "Ana María", "josé", "user_01@unam.mx"])
def test_ids_de_usuario_validos(id_valido):
    assert validar_id_destinatario(id_valido) == id_valido


# Validación estricta del contenedor

def test_key_id_con_salto_de_linea_final_es_rechazado(contenedor):
    alterado = copy.deepcopy(contenedor)
    alterado["recipients"][0]["key_id"] += "\n"

    with pytest.raises(ContenedorInvalido):
        validar_contenedor(alterado)


def test_base64_no_canonico_es_rechazado(contenedor):
    """Dos textos distintos no pueden representar los mismos bytes."""
    tabla = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    alterado = copy.deepcopy(contenedor)
    tag = alterado["tag"]

    assert tag.endswith("==")  # 16 bytes -> 2 bytes de relleno

    indice = tabla.index(tag[-3])
    # Cambia solo los bits de relleno (los 4 bajos): los mismos bytes decodificados
    alterado["tag"] = tag[:-3] + tabla[indice ^ 1] + "=="

    assert base64.b64decode(alterado["tag"], validate=True) == base64.b64decode(tag)

    with pytest.raises(ContenedorInvalido):
        validar_contenedor(alterado)


@pytest.mark.parametrize("version", [2.0, True, "2", None])
def test_version_debe_ser_el_entero_2(contenedor, version):
    alterado = copy.deepcopy(contenedor)
    alterado["header"]["version"] = version

    with pytest.raises(ContenedorInvalido):
        validar_contenedor(alterado)


@pytest.mark.parametrize("campo", ["nombre_archivo", "fecha"])
@pytest.mark.parametrize("valor", ["", 123, None, "x\ud800y"])
def test_campos_de_encabezado_invalidos(contenedor, campo, valor):
    alterado = copy.deepcopy(contenedor)
    alterado["header"][campo] = valor

    with pytest.raises(ContenedorInvalido):
        validar_contenedor(alterado)


def test_ids_que_difieren_solo_en_mayusculas_son_duplicados(contenedor):
    alterado = copy.deepcopy(contenedor)
    alterado["recipients"][0]["id"] = "Bob"
    alterado["recipients"][1]["id"] = "bob"

    with pytest.raises(ContenedorInvalido):
        validar_contenedor(alterado)


@pytest.mark.parametrize(
    "campo",
    [
        "nombre_archivo",
        "fecha",
        "version",
        "algoritmo",
        "algoritmo_envoltura",
        "algoritmo_huella",
        "id_archivo",
    ],
)
def test_cada_campo_del_encabezado_esta_en_el_aad(contenedor, campo):
    """El AAD cambia si cualquier campo del encabezado cambia."""
    encabezado = contenedor["header"]
    destinatarios = contenedor["recipients"]

    modificado = copy.deepcopy(encabezado)
    modificado[campo] = "otro-valor"

    assert construir_aad(encabezado, destinatarios) != construir_aad(
        modificado, destinatarios
    )


@pytest.mark.parametrize("campo", ["id", "key_id", "encrypted_key"])
def test_cada_campo_de_destinatario_esta_en_el_aad(contenedor, campo):
    encabezado = contenedor["header"]
    destinatarios = copy.deepcopy(contenedor["recipients"])
    original = construir_aad(encabezado, destinatarios)

    destinatarios[0][campo] = "otro-valor"

    assert construir_aad(encabezado, destinatarios) != original


def test_guardado_atomico_no_deja_temporales(tmp_path, contenedor):
    ruta = tmp_path / "doc.vault"

    guardar_contenedor_compartido(contenedor, ruta)

    assert sorted(p.name for p in tmp_path.iterdir()) == ["doc.vault"]

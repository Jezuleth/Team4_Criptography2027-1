import base64
import copy
import json

import pytest
from cryptography.exceptions import InvalidTag

from vault.public_key import (
    DestinatarioNoAutorizado,
    ErrorDeAcceso,
    generar_par_claves,
    huella_clave_publica,
    verificar_huella,
)
from vault.shared_container import ContenedorInvalido
from vault.sharing import (
    abrir_archivo_compartido,
    cifrar_para_destinatarios,
    compartir_archivo,
    descifrar_como_destinatario,
)


def _copia(contenedor):
    return copy.deepcopy(contenedor)


# =====================================================================
# Pruebas requeridas por el D3
# =====================================================================

def test_archivo_compartido_con_dos_usuarios_ambos_descifran(
    contenedor, contenido, alice, bob
):
    assert descifrar_como_destinatario(contenedor, alice) == contenido
    assert descifrar_como_destinatario(contenedor, bob) == contenido


def test_usuario_no_autorizado_no_puede_descifrar(contenedor, mallory):
    with pytest.raises(DestinatarioNoAutorizado):
        descifrar_como_destinatario(contenedor, mallory)


def test_usuario_no_autorizado_aunque_el_contenedor_sea_publico(
    tmp_path, contenedor, mallory
):
    """El .vault puede estar expuesto: sin clave privada válida no se abre."""
    ruta = tmp_path / "publico.vault"
    ruta.write_text(json.dumps(contenedor), encoding="utf-8")

    with pytest.raises(DestinatarioNoAutorizado):
        descifrar_como_destinatario(ruta, mallory)


def _renombrar_alice(c):
    c["recipients"][0]["id"] = "mallory"


def _cambiar_key_id_de_alice(c):
    c["recipients"][0]["key_id"] = "0" * 64


def _intercambiar_orden(c):
    c["recipients"].reverse()


def _agregar_destinatario(c):
    c["recipients"].append(
        {
            "id": "mallory",
            "key_id": "f" * 64,
            "encrypted_key": base64.b64encode(bytes(256)).decode("ascii"),
        }
    )


def _alterar_clave_envuelta_de_alice(c):
    clave = bytearray(base64.b64decode(c["recipients"][0]["encrypted_key"]))
    clave[0] ^= 1
    c["recipients"][0]["encrypted_key"] = base64.b64encode(bytes(clave)).decode(
        "ascii"
    )


def _copiar_clave_de_bob_en_alice(c):
    c["recipients"][0]["encrypted_key"] = c["recipients"][1]["encrypted_key"]


@pytest.mark.parametrize(
    "alteracion",
    [
        _renombrar_alice,
        _cambiar_key_id_de_alice,
        _intercambiar_orden,
        _agregar_destinatario,
        _alterar_clave_envuelta_de_alice,
        _copiar_clave_de_bob_en_alice,
    ],
)
def test_lista_de_destinatarios_alterada_hace_fallar_el_descifrado(
    contenedor, bob, alteracion
):
    """
    Bob NO fue tocado en ninguna alteración: aun así, descifrar falla
    porque la lista completa de destinatarios está autenticada en el AAD.
    """
    alterado = _copia(contenedor)
    alteracion(alterado)

    with pytest.raises(InvalidTag):
        descifrar_como_destinatario(alterado, bob)


def test_alterar_la_propia_entrada_hace_fallar_el_descifrado(contenedor, bob):
    """Cambiar el id de la entrada de Bob rompe la etiqueta OAEP."""
    alterado = _copia(contenedor)
    alterado["recipients"][1]["id"] = "robert"

    with pytest.raises(ErrorDeAcceso):
        descifrar_como_destinatario(alterado, bob)


def test_clave_privada_incorrecta_falla(contenedor, alice, bob, mallory):
    # Clave de un tercero
    with pytest.raises(DestinatarioNoAutorizado):
        descifrar_como_destinatario(contenedor, mallory)

    # Bob intenta abrir presentándose como Alice
    with pytest.raises(DestinatarioNoAutorizado):
        descifrar_como_destinatario(contenedor, bob, id_usuario="alice")

    # Alice con un par de claves nuevo (no el que se usó al compartir)
    alice_con_otra_clave = generar_par_claves(2048)

    with pytest.raises(DestinatarioNoAutorizado):
        descifrar_como_destinatario(contenedor, alice_con_otra_clave, "alice")


def test_clave_privada_incorrecta_sobre_entrada_ajena(contenedor, alice, bob):
    """
    Si la entrada de Alice se reetiqueta con la huella de Bob, la clave
    privada de Bob la encuentra pero no puede desenvolver ni autenticar.
    """
    alterado = _copia(contenedor)
    huella_bob = huella_clave_publica(bob.public_key())

    alterado["recipients"] = [
        {**alterado["recipients"][0], "key_id": huella_bob},
    ]

    with pytest.raises(ErrorDeAcceso):
        descifrar_como_destinatario(alterado, bob)


def test_eliminar_una_entrada_de_destinatario_rompe_el_acceso(
    contenedor, alice, bob
):
    sin_bob = _copia(contenedor)
    sin_bob["recipients"] = [sin_bob["recipients"][0]]

    # Bob ya no tiene entrada: pierde el acceso
    with pytest.raises(DestinatarioNoAutorizado):
        descifrar_como_destinatario(sin_bob, bob)

    # Alice conserva su entrada, pero la lista cambió: el AAD no coincide
    with pytest.raises(InvalidTag):
        descifrar_como_destinatario(sin_bob, alice)


def test_eliminar_todas_las_entradas_es_un_contenedor_invalido(contenedor, alice):
    sin_nadie = _copia(contenedor)
    sin_nadie["recipients"] = []

    with pytest.raises(ContenedorInvalido):
        descifrar_como_destinatario(sin_nadie, alice)


# =====================================================================
# Cobertura adicional
# =====================================================================

def test_tres_destinatarios(alice, bob, carol, contenido):
    contenedor = cifrar_para_destinatarios(
        contenido,
        "x.txt",
        {
            "alice": alice.public_key(),
            "bob": bob.public_key(),
            "carol": carol.public_key(),
        },
    )

    for clave in (alice, bob, carol):
        assert descifrar_como_destinatario(contenedor, clave) == contenido


def test_un_solo_destinatario(alice, contenido):
    contenedor = cifrar_para_destinatarios(
        contenido, "x.txt", {"alice": alice.public_key()}
    )

    assert descifrar_como_destinatario(contenedor, alice) == contenido


def test_id_usuario_correcto_es_aceptado(contenedor, contenido, alice, bob):
    assert descifrar_como_destinatario(contenedor, alice, "alice") == contenido
    assert descifrar_como_destinatario(contenedor, bob, "bob") == contenido


def test_archivo_se_cifra_una_sola_vez(contenedor):
    """Hay un único ciphertext y una entrada de clave por destinatario."""
    assert len(contenedor["recipients"]) == 2
    assert isinstance(contenedor["ciphertext"], str)


def test_claves_envueltas_distintas_por_destinatario(contenedor):
    claves = {r["encrypted_key"] for r in contenedor["recipients"]}

    assert len(claves) == 2


def test_key_id_corresponde_a_la_huella_de_la_clave_publica(
    contenedor, alice, bob
):
    assert contenedor["recipients"][0]["key_id"] == huella_clave_publica(
        alice.public_key()
    )
    assert contenedor["recipients"][1]["key_id"] == huella_clave_publica(
        bob.public_key()
    )


def test_dos_cifrados_del_mismo_archivo_son_distintos(alice, bob, contenido):
    destinatarios = {"alice": alice.public_key(), "bob": bob.public_key()}

    c1 = cifrar_para_destinatarios(contenido, "x.txt", destinatarios)
    c2 = cifrar_para_destinatarios(contenido, "x.txt", destinatarios)

    assert c1["ciphertext"] != c2["ciphertext"]
    assert c1["nonce"] != c2["nonce"]
    assert c1["header"]["id_archivo"] != c2["header"]["id_archivo"]


def test_archivo_vacio(alice, contenido):
    contenedor = cifrar_para_destinatarios(
        b"", "vacio.txt", {"alice": alice.public_key()}
    )

    assert descifrar_como_destinatario(contenedor, alice) == b""


def test_archivo_grande_no_pasa_por_rsa(alice, bob, tmp_path):
    """RSA solo envuelve 32 bytes: el tamaño de la clave no depende del archivo."""
    origen = tmp_path / "grande.bin"
    datos = bytes(range(256)) * 8192  # 2 MiB
    origen.write_bytes(datos)

    ruta = tmp_path / "grande.vault"
    compartir_archivo(
        origen,
        ruta,
        {"alice": alice.public_key(), "bob": bob.public_key()},
    )

    contenedor = json.loads(ruta.read_text(encoding="utf-8"))

    for entrada in contenedor["recipients"]:
        assert len(base64.b64decode(entrada["encrypted_key"])) == 256

    salida = tmp_path / "recuperado.bin"
    recuperado = abrir_archivo_compartido(ruta, bob, "bob", salida)

    assert recuperado == datos
    assert salida.read_bytes() == datos


def test_viaje_por_disco(tmp_path, alice, bob):
    origen = tmp_path / "nota.txt"
    origen.write_bytes(b"hola equipo")

    ruta = tmp_path / "nota.vault"
    compartir_archivo(
        origen, ruta, {"alice": alice.public_key(), "bob": bob.public_key()}
    )

    assert abrir_archivo_compartido(ruta, alice) == b"hola equipo"
    assert abrir_archivo_compartido(ruta, bob) == b"hola equipo"


def test_el_contenedor_no_contiene_el_texto_plano(contenedor, contenido):
    assert contenido.decode() not in json.dumps(contenedor)


# Alteraciones del contenido y del encabezado

@pytest.mark.parametrize("campo", ["ciphertext", "tag", "nonce"])
def test_alterar_contenido_cifrado_falla(contenedor, alice, campo):
    alterado = _copia(contenedor)
    datos = bytearray(base64.b64decode(alterado[campo]))
    datos[0] ^= 1
    alterado[campo] = base64.b64encode(bytes(datos)).decode("ascii")

    with pytest.raises(InvalidTag):
        descifrar_como_destinatario(alterado, alice)


def test_alterar_metadatos_falla(contenedor, alice):
    alterado = _copia(contenedor)
    alterado["header"]["nombre_archivo"] = "otro.txt"

    with pytest.raises(InvalidTag):
        descifrar_como_destinatario(alterado, alice)


def test_alterar_fecha_falla(contenedor, alice):
    alterado = _copia(contenedor)
    alterado["header"]["fecha"] = "1999-01-01T00:00:00+00:00"

    with pytest.raises(InvalidTag):
        descifrar_como_destinatario(alterado, alice)


def test_cambiar_identificadores_de_algoritmo_es_rechazado(contenedor, alice):
    alterado = _copia(contenedor)
    alterado["header"]["algoritmo_envoltura"] = "RSA-PKCS1v15"

    with pytest.raises(ContenedorInvalido):
        descifrar_como_destinatario(alterado, alice)


def test_entrada_de_otro_contenedor_no_sirve(alice, bob, contenido):
    """La etiqueta OAEP ata cada clave envuelta a su archivo concreto."""
    destinatarios = {"alice": alice.public_key(), "bob": bob.public_key()}

    c1 = cifrar_para_destinatarios(contenido, "x.txt", destinatarios)
    c2 = cifrar_para_destinatarios(contenido, "x.txt", destinatarios)

    mezclado = _copia(c2)
    mezclado["recipients"][0] = c1["recipients"][0]

    with pytest.raises(ErrorDeAcceso):
        descifrar_como_destinatario(mezclado, alice)


# Entradas inválidas al cifrar

def test_sin_destinatarios(contenido):
    with pytest.raises(ValueError):
        cifrar_para_destinatarios(contenido, "x.txt", {})


def test_misma_clave_publica_bajo_dos_ids(alice, contenido):
    with pytest.raises(ValueError):
        cifrar_para_destinatarios(
            contenido,
            "x.txt",
            {"alice": alice.public_key(), "alicia": alice.public_key()},
        )


def test_ids_que_difieren_solo_en_mayusculas(alice, bob, contenido):
    with pytest.raises(ValueError):
        cifrar_para_destinatarios(
            contenido,
            "x.txt",
            {"Alice": alice.public_key(), "alice": bob.public_key()},
        )


def test_id_de_destinatario_vacio(alice, contenido):
    with pytest.raises(ValueError):
        cifrar_para_destinatarios(
            contenido, "x.txt", {"": alice.public_key()}
        )


def test_clave_publica_invalida_como_destinatario(contenido):
    with pytest.raises(ValueError):
        cifrar_para_destinatarios(contenido, "x.txt", {"alice": "no-es-una-clave"})


# Decisión de seguridad: clave pública equivocada

def test_clave_publica_equivocada_da_acceso_a_la_persona_equivocada(
    alice, bob, mallory, contenido
):
    """
    Si se comparte "con Bob" usando por error la clave pública de Mallory,
    el sistema no puede saberlo: Mallory entra, Bob queda fuera.
    La defensa es verificar la huella ANTES de compartir.
    """
    contenedor = cifrar_para_destinatarios(
        contenido,
        "x.txt",
        {"alice": alice.public_key(), "bob": mallory.public_key()},
    )

    assert descifrar_como_destinatario(contenedor, mallory) == contenido

    with pytest.raises(DestinatarioNoAutorizado):
        descifrar_como_destinatario(contenedor, bob)

    # La verificación de huella (canal de confianza) detecta el error
    with pytest.raises(ValueError):
        verificar_huella(
            mallory.public_key(), huella_clave_publica(bob.public_key())
        )

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from vault.public_key import (
    ErrorDeAcceso,
    cargar_clave_privada,
    cargar_clave_publica,
    crear_etiqueta_envoltura,
    desenvolver_clave,
    envolver_clave,
    generar_par_claves,
    huella_clave_publica,
    serializar_clave_privada,
    serializar_clave_publica,
    validar_clave_publica,
    verificar_huella,
)

ETIQUETA = crear_etiqueta_envoltura("archivo-1", "huella-1", "alice")


# Huellas (key IDs)

def test_huella_es_determinista(alice):
    huella_1 = huella_clave_publica(alice.public_key())
    huella_2 = huella_clave_publica(alice.public_key())

    assert huella_1 == huella_2
    assert len(huella_1) == 64


def test_huellas_distintas_para_claves_distintas(alice, bob):
    assert huella_clave_publica(alice.public_key()) != huella_clave_publica(
        bob.public_key()
    )


def test_huella_sobrevive_a_serializacion_pem(alice):
    pem = serializar_clave_publica(alice.public_key())
    recargada = cargar_clave_publica(pem)

    assert huella_clave_publica(recargada) == huella_clave_publica(
        alice.public_key()
    )


def test_verificar_huella_correcta(alice):
    huella = huella_clave_publica(alice.public_key())

    verificar_huella(alice.public_key(), huella)
    verificar_huella(alice.public_key(), huella.upper())


def test_verificar_huella_detecta_clave_sustituida(alice, mallory):
    huella_de_alice = huella_clave_publica(alice.public_key())

    with pytest.raises(ValueError):
        verificar_huella(mallory.public_key(), huella_de_alice)


# Validación de claves

def test_rechaza_rsa_menor_a_2048_bits():
    with pytest.raises(ValueError):
        generar_par_claves(1024)


def test_rechaza_clave_publica_rsa_debil():
    clave_debil = rsa.generate_private_key(public_exponent=65537, key_size=1024)

    with pytest.raises(ValueError):
        validar_clave_publica(clave_debil.public_key())


def test_rechaza_exponente_publico_distinto_de_65537(alice):
    numeros = alice.public_key().public_numbers()
    clave_e3 = rsa.RSAPublicNumbers(3, numeros.n).public_key()

    with pytest.raises(ValueError):
        validar_clave_publica(clave_e3)


def test_cargar_pem_sin_cifrar_con_contrasena(alice):
    from cryptography.hazmat.primitives import serialization

    pem_sin_cifrar = alice.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    with pytest.raises(ValueError):
        cargar_clave_privada(pem_sin_cifrar, "cualquiera")


def test_rechaza_clave_que_no_es_rsa():
    clave_ec = ec.generate_private_key(ec.SECP256R1())

    with pytest.raises(ValueError):
        validar_clave_publica(clave_ec.public_key())


def test_tamano_por_defecto_es_3072(monkeypatch):
    capturado = {}
    generar_original = rsa.generate_private_key

    def falso_generar(public_exponent, key_size):
        capturado["bits"] = key_size
        # Se genera una clave pequeña para no tardar en la prueba
        return generar_original(public_exponent, 2048)

    monkeypatch.setattr(rsa, "generate_private_key", falso_generar)

    generar_par_claves()

    assert capturado["bits"] == 3072


# Serialización de claves privadas

def test_clave_privada_pem_cifrada_ida_y_vuelta(alice):
    pem = serializar_clave_privada(alice, "ClaveDelPEM123")

    assert b"ENCRYPTED" in pem

    recargada = cargar_clave_privada(pem, "ClaveDelPEM123")

    assert huella_clave_publica(recargada.public_key()) == huella_clave_publica(
        alice.public_key()
    )


def test_clave_privada_pem_contrasena_incorrecta(alice):
    pem = serializar_clave_privada(alice, "ClaveDelPEM123")

    with pytest.raises(ValueError):
        cargar_clave_privada(pem, "otra-contraseña")


def test_exportar_clave_privada_sin_contrasena(alice):
    with pytest.raises(ValueError):
        serializar_clave_privada(alice, "")


# Envoltura RSA-OAEP

def test_envolver_y_desenvolver(alice):
    clave = bytes(range(32))

    envuelta = envolver_clave(clave, alice.public_key(), ETIQUETA)

    assert envuelta != clave
    assert desenvolver_clave(envuelta, alice, ETIQUETA) == clave


def test_envoltura_es_probabilistica(alice):
    clave = bytes(32)

    assert envolver_clave(clave, alice.public_key(), ETIQUETA) != envolver_clave(
        clave, alice.public_key(), ETIQUETA
    )


def test_no_se_pueden_envolver_datos_grandes(alice):
    """RSA solo recibe claves simétricas de 32 bytes, nunca archivos."""
    with pytest.raises(ValueError):
        envolver_clave(b"A" * 100, alice.public_key(), ETIQUETA)

    with pytest.raises(ValueError):
        envolver_clave(b"A" * 31, alice.public_key(), ETIQUETA)


def test_desenvolver_con_clave_privada_incorrecta(alice, bob):
    envuelta = envolver_clave(bytes(32), alice.public_key(), ETIQUETA)

    with pytest.raises(ErrorDeAcceso):
        desenvolver_clave(envuelta, bob, ETIQUETA)


def test_desenvolver_con_etiqueta_distinta(alice):
    envuelta = envolver_clave(bytes(32), alice.public_key(), ETIQUETA)

    otra_etiqueta = crear_etiqueta_envoltura("archivo-2", "huella-1", "alice")

    with pytest.raises(ErrorDeAcceso):
        desenvolver_clave(envuelta, alice, otra_etiqueta)


def test_desenvolver_datos_alterados(alice):
    envuelta = bytearray(envolver_clave(bytes(32), alice.public_key(), ETIQUETA))
    envuelta[10] ^= 1

    with pytest.raises(ErrorDeAcceso):
        desenvolver_clave(bytes(envuelta), alice, ETIQUETA)

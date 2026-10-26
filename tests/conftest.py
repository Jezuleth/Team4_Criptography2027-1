import pytest

from vault.public_key import generar_par_claves
from vault.sharing import cifrar_para_destinatarios


@pytest.fixture(scope="session")
def alice():
    # 2048 bits es el mínimo permitido; acelera las pruebas.
    return generar_par_claves(2048)


@pytest.fixture(scope="session")
def bob():
    return generar_par_claves(2048)


@pytest.fixture(scope="session")
def carol():
    return generar_par_claves(2048)


@pytest.fixture(scope="session")
def mallory():
    """Usuario NO autorizado: nunca se agrega como destinatario."""
    return generar_par_claves(2048)


@pytest.fixture
def contenido():
    return b"Contrato confidencial del D3"


@pytest.fixture
def contenedor(alice, bob, contenido):
    """Archivo compartido con Alice y Bob."""
    return cifrar_para_destinatarios(
        contenido,
        "contrato.txt",
        {
            "alice": alice.public_key(),
            "bob": bob.public_key(),
        },
    )

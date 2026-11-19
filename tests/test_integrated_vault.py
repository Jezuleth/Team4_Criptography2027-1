
import pytest

from vault.integrated_vault import (
    crear_identidad,
    recuperar_identidad,
    registrar_identidad_en_gestor,
    enviar_archivo,
    recibir_archivo,
)
from vault.key_lifecycle import GestorCicloVida, ErrorCicloVida


def test_integracion_completa_d2_d3_d5_d6(tmp_path):
    password = "PasswordSegura123!"

    carpeta_alice = tmp_path / "alice"
    carpeta_bob = tmp_path / "bob"

    # 1. Crear identidades protegidas con contraseña.
    crear_identidad("alice", password, carpeta_alice)
    crear_identidad("bob", password, carpeta_bob)

    # 2. Crear gestor D6 con estado persistente.
    ruta_estado = tmp_path / "estado_claves.json"

    gestor = GestorCicloVida(
        ruta_estado=ruta_estado,
        password_estado=password,
    )

    registrar_identidad_en_gestor(
        "bob", carpeta_bob, password, gestor
    )

    # 3. Recuperar claves después de guardarlas.
    alice = recuperar_identidad(password, carpeta_alice)
    bob = recuperar_identidad(password, carpeta_bob)

    # 4. Crear un documento.
    documento = tmp_path / "documento.txt"
    documento.write_text(
        "Documento confidencial para Bob",
        encoding="utf-8",
    )

    # 5. Alice cifra y firma el archivo para Bob.
    archivo_vault = tmp_path / "documento.vault"

    enviar_archivo(
        documento,
        archivo_vault,
        {"bob": bob["clave_ecies"].public_key()},
        carpeta_alice,
        password,
    )

    # 6. Simular reinicio del gestor D6.
    gestor = GestorCicloVida(
        ruta_estado=ruta_estado,
        password_estado=password,
    )

    # 7. Bob verifica la firma y descifra.
    recuperado = tmp_path / "recuperado.txt"

    recibir_archivo(
        archivo_vault,
        recuperado,
        "bob",
        carpeta_bob,
        password,
        alice["clave_firma"].public_key(),
        gestor,
    )

    assert recuperado.read_bytes() == documento.read_bytes()

    # 8. Revocar la clave de Bob.
    gestor.revocar_clave("bob", "Clave comprometida")

    # 9. Verificar que D6 bloquea el descifrado.
    with pytest.raises(ErrorCicloVida):
        recibir_archivo(
            archivo_vault,
            tmp_path / "rechazado.txt",
            "bob",
            carpeta_bob,
            password,
            alice["clave_firma"].public_key(),
            gestor,
        )

from vault.key_backup import crear_backup, restaurar_backup


def test_backup_y_restauracion_integrada(tmp_path):
    password = "PasswordSegura123!"

    carpeta = tmp_path / "bob"
    crear_identidad("bob", password, carpeta)

    original = carpeta / "ecies.keystore"
    respaldo = tmp_path / "bob_backup.keystore"

    # Crear respaldo.
    crear_backup(original, respaldo, password)

    # Simular pérdida del keystore original.
    original.unlink()

    # Restaurar desde el respaldo.
    restaurar_backup(respaldo, original, password)

    # Recuperar la identidad.
    identidad = recuperar_identidad(password, carpeta)

    assert identidad["clave_ecies"] is not None
    assert identidad["clave_firma"] is not None

from vault.public_key import (
    huella_clave_publica,
    verificar_huella,
    generar_par_claves,
)


def test_sustitucion_clave_publica_detectada(tmp_path):
    password = "PasswordSegura123!"
    carpeta_bob = tmp_path / "bob"

    crear_identidad("bob", password, carpeta_bob)
    bob = recuperar_identidad(password, carpeta_bob)

    # Huella confiable de Bob.
    huella_bob = huella_clave_publica(
        bob["clave_ecies"].public_key()
    )

    # Mallory intenta sustituir la clave pública de Bob.
    clave_falsa = generar_par_claves().public_key()

    with pytest.raises(ValueError):
        verificar_huella(clave_falsa, huella_bob)

    # La clave legítima sí debe aceptarse.
    verificar_huella(
        bob["clave_ecies"].public_key(),
        huella_bob,
    )

from vault.integrated_vault import enviar_archivo_verificado


def test_envio_verificado_y_sustitucion_rechazada(tmp_path):
    password = "PasswordSegura123!"

    carpeta_alice = tmp_path / "alice"
    carpeta_bob = tmp_path / "bob"

    crear_identidad("alice", password, carpeta_alice)
    crear_identidad("bob", password, carpeta_bob)

    bob = recuperar_identidad(password, carpeta_bob)
    clave_bob = bob["clave_ecies"].public_key()

    huella_bob = huella_clave_publica(clave_bob)

    documento = tmp_path / "documento.txt"
    documento.write_text("Archivo confidencial", encoding="utf-8")

    # Envío legítimo.
    vault_valido = tmp_path / "valido.vault"

    enviar_archivo_verificado(
        documento,
        vault_valido,
        {"bob": clave_bob},
        {"bob": huella_bob},
        carpeta_alice,
        password,
    )

    assert vault_valido.exists()

    # Mallory sustituye la clave pública de Bob.
    clave_falsa = generar_par_claves().public_key()
    vault_falso = tmp_path / "falso.vault"

    with pytest.raises(ValueError):
        enviar_archivo_verificado(
            documento,
            vault_falso,
            {"bob": clave_falsa},
            {"bob": huella_bob},
            carpeta_alice,
            password,
        )

    # El archivo fraudulento nunca debe generarse.
    assert not vault_falso.exists()

from vault.signatures import ErrorFirma


def test_remitente_falso_rechazado(tmp_path):
    password = "PasswordSegura123!"

    carpeta_alice = tmp_path / "alice"
    carpeta_bob = tmp_path / "bob"
    carpeta_mallory = tmp_path / "mallory"

    crear_identidad("alice", password, carpeta_alice)
    crear_identidad("bob", password, carpeta_bob)
    crear_identidad("mallory", password, carpeta_mallory)

    alice = recuperar_identidad(password, carpeta_alice)
    bob = recuperar_identidad(password, carpeta_bob)

    gestor = GestorCicloVida()
    registrar_identidad_en_gestor(
        "bob", carpeta_bob, password, gestor
    )

    documento = tmp_path / "documento.txt"
    documento.write_text("Documento confidencial", encoding="utf-8")

    # Mallory firma el documento con su propia identidad.
    archivo = tmp_path / "documento.vault"

    enviar_archivo(
        documento,
        archivo,
        {"bob": bob["clave_ecies"].public_key()},
        carpeta_mallory,
        password,
    )

    # Bob espera un documento firmado por Alice.
    with pytest.raises(ErrorFirma):
        recibir_archivo(
            archivo,
            tmp_path / "recuperado.txt",
            "bob",
            carpeta_bob,
            password,
            alice["clave_firma"].public_key(),
            gestor,
        )

    assert not (tmp_path / "recuperado.txt").exists()

def test_restauracion_y_descifrado_completo(tmp_path):
    password = "PasswordSegura123!"

    carpeta_alice = tmp_path / "alice"
    carpeta_bob = tmp_path / "bob"

    crear_identidad("alice", password, carpeta_alice)
    crear_identidad("bob", password, carpeta_bob)

    alice = recuperar_identidad(password, carpeta_alice)
    bob = recuperar_identidad(password, carpeta_bob)

    # Registrar la identidad de Bob en D6.
    ruta_estado = tmp_path / "estado_claves.json"
    gestor = GestorCicloVida(
        ruta_estado=ruta_estado,
        password_estado=password,
    )
    registrar_identidad_en_gestor(
        "bob", carpeta_bob, password, gestor
    )

    # Alice envía un archivo firmado a Bob.
    origen = tmp_path / "documento.txt"
    origen.write_text("Archivo confidencial", encoding="utf-8")

    vault = tmp_path / "documento.vault"
    enviar_archivo(
        origen,
        vault,
        {"bob": bob["clave_ecies"].public_key()},
        carpeta_alice,
        password,
    )

    # Respaldar el keystore de Bob.
    original = carpeta_bob / "ecies.keystore"
    respaldo = tmp_path / "respaldo_bob.keystore"
    crear_backup(original, respaldo, password)

    # Simular pérdida de la clave y reinicio.
    original.unlink()
    del bob

    # Restaurar el keystore.
    restaurar_backup(respaldo, original, password)

    gestor = GestorCicloVida(
        ruta_estado=ruta_estado,
        password_estado=password,
    )

    # Bob recupera el documento.
    salida = tmp_path / "recuperado.txt"
    recibir_archivo(
        vault,
        salida,
        "bob",
        carpeta_bob,
        password,
        alice["clave_firma"].public_key(),
        gestor,
    )

    assert salida.read_bytes() == origen.read_bytes()

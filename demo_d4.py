
from pathlib import Path
import json

from cryptography.exceptions import InvalidTag

from vault.public_key import (
    generar_par_claves,
    DestinatarioNoAutorizado,
)
from vault.sharing import (
    compartir_archivo,
    abrir_archivo_compartido,
)

# Carpeta temporal para las evidencias de D4
carpeta = Path("demo_d4_archivos")
carpeta.mkdir(exist_ok=True)

original = carpeta / "mensaje.txt"
vault = carpeta / "mensaje.vault"

print("\n=== D4 - SECURE DIGITAL DOCUMENT VAULT ===")

# 1. Generar claves para tres usuarios
print("\n[1] Generando claves RSA...")
alice = generar_par_claves()
bob = generar_par_claves()
mallory = generar_par_claves()

# 2. Crear el archivo original
mensaje = b"Documento confidencial del Equipo 4 - UNAM"
original.write_bytes(mensaje)

# 3. Cifrar para Alice y Bob
print("\n[2] Cifrando archivo para Alice y Bob...")

compartir_archivo(
    original,
    vault,
    {
        "alice": alice.public_key(),
        "bob": bob.public_key(),
    },
)

print("OK: Contenedor mensaje.vault creado.")

# 4. Descifrado autorizado
print("\n[3] Descifrado de usuarios autorizados...")

for nombre, clave in [("alice", alice), ("bob", bob)]:
    recuperado = abrir_archivo_compartido(
        vault,
        clave,
        id_usuario=nombre,
        ruta_salida=carpeta / f"recuperado_{nombre}.txt",
    )
    assert recuperado == mensaje
    print(f"OK: {nombre} recupero el archivo original.")

# 5. Usuario no autorizado
print("\n[4] Intento de acceso no autorizado...")

try:
    abrir_archivo_compartido(
        vault,
        mallory,
        id_usuario="mallory",
    )
except DestinatarioNoAutorizado:
    print("OK: Mallory fue rechazado.")
else:
    raise AssertionError("ERROR: Mallory pudo descifrar.")

# 6. Alteracion del contenido cifrado
print("\n[5] Simulando manipulacion del contenedor...")

contenedor = json.loads(vault.read_text(encoding="utf-8"))

# Cambiar un caracter Base64 valido del ciphertext
cifrado = contenedor["ciphertext"]
assert cifrado, "El ciphertext esta vacio."

contenedor["ciphertext"] = (
    ("A" if cifrado[0] != "A" else "B") + cifrado[1:]
)

alterado = carpeta / "mensaje_alterado.vault"
alterado.write_text(
    json.dumps(contenedor),
    encoding="utf-8",
)

# Verificar que AES-GCM detecta la manipulacion
try:
    abrir_archivo_compartido(
        alterado,
        bob,
        id_usuario="bob",
    )
except InvalidTag:
    print("OK: AES-GCM detecto la manipulacion.")
else:
    raise AssertionError("ERROR: Se acepto el archivo alterado.")

print("\n=== DEMOSTRACION D4 FINALIZADA ===")

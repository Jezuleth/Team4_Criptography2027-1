
from pathlib import Path

from vault.integrated_vault import crear_identidad

CARPETA = Path("identidades_demo")


def preparar_demo():
    print("Preparando identidades de demostración...\n")

    for usuario in ("alice", "bob", "mallory"):
        carpeta = CARPETA / usuario
        ruta_ecies = carpeta / "ecies.keystore"
        ruta_firma = carpeta / "firma.keystore"

        if ruta_ecies.exists() or ruta_firma.exists():
            print(f"{usuario}: identidad existente")
            continue

        password = input(
            f"Contraseña para {usuario} (mínimo 12 caracteres): "
        )

        identidad = crear_identidad(
            usuario,
            password,
            carpeta,
        )

        print(f"{usuario}: identidad creada")
        print(f"Huella de firma: {identidad['signer_id']}\n")

    print("\nIdentidades preparadas.")


if __name__ == "__main__":
    preparar_demo()

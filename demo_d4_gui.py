
import base64
import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext

from cryptography.exceptions import InvalidTag

from vault.public_key import (
    generar_par_claves,
    DestinatarioNoAutorizado,
)
from vault.sharing import (
    compartir_archivo,
    abrir_archivo_compartido,
)


# ---------- CONFIGURACION ----------

BASE = Path(__file__).resolve().parent
SALIDA = BASE / "demo_d4_archivos"
SALIDA.mkdir(exist_ok=True)

BG = "#0F172A"
PANEL = "#1E293B"
TEXT = "#F8FAFC"
MUTED = "#94A3B8"
BLUE = "#38BDF8"
GREEN = "#4ADE80"
RED = "#F87171"


class VaultGUI(tk.Tk):

    def __init__(self):
        super().__init__()

        self.title("Secure Digital Document Vault - Team 4")
        self.geometry("1050x790")
        self.minsize(850, 650)
        self.configure(bg=BG)

        self.archivo = None
        self.vault = SALIDA / "documento.vault"
        self.vault_alterado = SALIDA / "documento_alterado.vault"

        self.claves = {}
        self.cifrado_listo = False
        self.alterado_listo = False

        self.estado = tk.StringVar(value="READY")
        self.nombre_archivo = tk.StringVar(
            value="No document selected"
        )

        self.crear_interfaz()

    def etiqueta(self, padre, texto, size=11, color=TEXT,
                 bold=False):
        return tk.Label(
            padre,
            text=texto,
            font=("Segoe UI", size, "bold" if bold else "normal"),
            fg=color,
            bg=padre.cget("bg"),
            anchor="w",
        )

    def boton(self, padre, texto, comando, color=BLUE):
        return tk.Button(
            padre,
            text=texto,
            command=comando,
            bg=color,
            fg="#0F172A",
            activebackground=color,
            font=("Segoe UI", 10, "bold"),
            relief="flat",
            cursor="hand2",
            padx=15,
            pady=11,
        )

    def registrar(self, mensaje):
        self.log.configure(state="normal")
        self.log.insert("end", mensaje + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def mostrar_datos(self, texto):
        self.vista.configure(state="normal")
        self.vista.delete("1.0", "end")
        self.vista.insert("end", texto)
        self.vista.configure(state="disabled")

    def crear_interfaz(self):

        cabecera = tk.Frame(self, bg=BG)
        cabecera.pack(fill="x", padx=28, pady=(22, 12))

        self.etiqueta(
            cabecera,
            "SECURE DIGITAL DOCUMENT VAULT",
            21,
            TEXT,
            True,
        ).pack(anchor="w")

        self.etiqueta(
            cabecera,
            "TEAM 4 · UNAM · INTERACTIVE D4 SECURITY LAB",
            10,
            BLUE,
        ).pack(anchor="w", pady=4)

        # Archivo
        archivo_panel = tk.Frame(self, bg=PANEL, padx=18, pady=15)
        archivo_panel.pack(fill="x", padx=28, pady=8)

        self.etiqueta(
            archivo_panel, "1. SELECT DOCUMENT", 12, BLUE, True
        ).pack(anchor="w")

        fila_archivo = tk.Frame(archivo_panel, bg=PANEL)
        fila_archivo.pack(fill="x", pady=(10, 0))

        self.etiqueta(
            fila_archivo, "File:", 10, MUTED
        ).pack(side="left")

        tk.Label(
            fila_archivo,
            textvariable=self.nombre_archivo,
            fg=TEXT,
            bg=PANEL,
            font=("Segoe UI", 10),
        ).pack(side="left", padx=12)

        self.boton(
            fila_archivo,
            "BROWSE FILE",
            self.seleccionar_archivo,
        ).pack(side="right")

        # Cifrado
        cifrado_panel = tk.Frame(self, bg=PANEL, padx=18, pady=15)
        cifrado_panel.pack(fill="x", padx=28, pady=8)

        self.etiqueta(
            cifrado_panel,
            "2. ENCRYPT & SHARE",
            12,
            BLUE,
            True,
        ).pack(anchor="w")

        self.etiqueta(
            cifrado_panel,
            "AES-256-GCM encrypts the document once. "
            "ECIES (secp256k1) protects its key for Alice and Bob.",
            10,
            MUTED,
        ).pack(anchor="w", pady=7)

        self.boton(
            cifrado_panel,
            "ENCRYPT FOR ALICE + BOB",
            self.cifrar,
        ).pack(fill="x", pady=(6, 0))

        # Destinatarios
        usuarios_panel = tk.Frame(self, bg=PANEL, padx=18, pady=15)
        usuarios_panel.pack(fill="x", padx=28, pady=8)

        self.etiqueta(
            usuarios_panel,
            "3. TEST RECIPIENT ACCESS",
            12,
            BLUE,
            True,
        ).pack(anchor="w")

        fila_usuarios = tk.Frame(usuarios_panel, bg=PANEL)
        fila_usuarios.pack(fill="x", pady=(12, 0))

        for nombre, color in [
            ("alice", GREEN),
            ("bob", GREEN),
            ("mallory", RED),
        ]:
            self.boton(
                fila_usuarios,
                f"DECRYPT AS {nombre.upper()}",
                lambda n=nombre: self.descifrar(n),
                color,
            ).pack(side="left", expand=True, fill="x", padx=4)

        # Ataque
        ataque_panel = tk.Frame(self, bg=PANEL, padx=18, pady=15)
        ataque_panel.pack(fill="x", padx=28, pady=8)

        self.etiqueta(
            ataque_panel,
            "4. TAMPERING ATTACK",
            12,
            RED,
            True,
        ).pack(anchor="w")

        self.etiqueta(
            ataque_panel,
            "Modify one byte of the encrypted document "
            "and test AES-GCM authentication.",
            10,
            MUTED,
        ).pack(anchor="w", pady=7)

        fila_ataque = tk.Frame(ataque_panel, bg=PANEL)
        fila_ataque.pack(fill="x")

        self.boton(
            fila_ataque,
            "TAMPER ENCRYPTED FILE",
            self.manipular,
            RED,
        ).pack(side="left", expand=True, fill="x", padx=4)

        self.boton(
            fila_ataque,
            "TRY DECRYPTING TAMPERED FILE",
            self.probar_manipulacion,
        ).pack(side="left", expand=True, fill="x", padx=4)

        # Visualizacion
        datos_panel = tk.Frame(self, bg=BG)
        datos_panel.pack(
            fill="both",
            expand=True,
            padx=28,
            pady=(12, 8),
        )

        izquierda = tk.Frame(datos_panel, bg=PANEL, padx=12, pady=12)
        izquierda.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(0, 6),
        )

        derecha = tk.Frame(datos_panel, bg=PANEL, padx=12, pady=12)
        derecha.pack(
            side="left",
            fill="both",
            expand=True,
            padx=(6, 0),
        )

        self.etiqueta(
            izquierda,
            "DOCUMENT / ENCRYPTED DATA",
            11,
            BLUE,
            True,
        ).pack(anchor="w", pady=(0, 8))

        self.vista = scrolledtext.ScrolledText(
            izquierda,
            bg=BG,
            fg=TEXT,
            font=("Consolas", 10),
            relief="flat",
            wrap="word",
            state="disabled",
        )
        self.vista.pack(fill="both", expand=True)

        self.etiqueta(
            derecha,
            "SECURITY EVENTS",
            11,
            BLUE,
            True,
        ).pack(anchor="w", pady=(0, 8))

        self.log = scrolledtext.ScrolledText(
            derecha,
            bg=BG,
            fg=GREEN,
            font=("Consolas", 10),
            relief="flat",
            wrap="word",
            state="disabled",
        )
        self.log.pack(fill="both", expand=True)

        barra = tk.Frame(self, bg=BG)
        barra.pack(fill="x", padx=28, pady=(4, 15))

        self.etiqueta(
            barra, "SYSTEM STATUS:", 10, MUTED, True
        ).pack(side="left")

        tk.Label(
            barra,
            textvariable=self.estado,
            fg=GREEN,
            bg=BG,
            font=("Segoe UI", 10, "bold"),
        ).pack(side="left", padx=10)

    def seleccionar_archivo(self):

        ruta = filedialog.askopenfilename(
            title="Select a document to encrypt"
        )

        if not ruta:
            return

        self.archivo = Path(ruta)
        self.nombre_archivo.set(self.archivo.name)

        # Seleccionar otro archivo invalida la sesion anterior.
        self.claves = {}
        self.cifrado_listo = False
        self.alterado_listo = False

        contenido = self.archivo.read_bytes()

        try:
            vista = contenido.decode("utf-8")
        except UnicodeDecodeError:
            vista = (
                "[Binary document]\n"
                f"Size: {len(contenido)} bytes\n\n"
                f"First bytes (hex):\n{contenido[:100].hex(' ')}"
            )

        self.mostrar_datos(
            "ORIGINAL DOCUMENT\n"
            "------------------------------\n"
            f"Name: {self.archivo.name}\n"
            f"Size: {len(contenido)} bytes\n\n"
            f"{vista[:2000]}"
        )

        self.registrar(
            f"[FILE] Selected: {self.archivo.name}"
        )
        self.estado.set("DOCUMENT SELECTED")

    def cifrar(self):

        if self.archivo is None:
            messagebox.showwarning(
                "Missing document",
                "Select a document first.",
            )
            return

        try:
            self.claves = {
                "alice": generar_par_claves(),
                "bob": generar_par_claves(),
                "mallory": generar_par_claves(),
            }

            destinatarios = {
                "alice": self.claves["alice"].public_key(),
                "bob": self.claves["bob"].public_key(),
            }

            compartir_archivo(
                self.archivo,
                self.vault,
                destinatarios,
            )

            contenedor = json.loads(
                self.vault.read_text(encoding="utf-8")
            )

            cifrado = base64.b64decode(
                contenedor["ciphertext"],
                validate=True,
            )

            self.cifrado_listo = True
            self.alterado_listo = False

            self.mostrar_datos(
                "ENCRYPTED DOCUMENT\n"
                "------------------------------\n"
                f"Container: {self.vault.name}\n"
                f"Original: {self.archivo.name}\n"
                f"Recipients: Alice, Bob\n"
                f"Ciphertext size: {len(cifrado)} bytes\n\n"
                "CIPHERTEXT (HEX PREVIEW)\n"
                f"{cifrado[:160].hex(' ')}\n\n"
                "The plaintext is not stored in this field."
            )

            self.registrar("[OK] Document encrypted using AES-GCM.")
            self.registrar("[OK] File key wrapped for Alice.")
            self.registrar("[OK] File key wrapped for Bob.")
            self.registrar("[OK] Encrypted .vault created.")

            self.estado.set("ENCRYPTED")

        except Exception as error:
            self.cifrado_listo = False
            self.registrar(
                f"[ERROR] Encryption: {type(error).__name__}: {error}"
            )
            messagebox.showerror("Encryption failed", str(error))

    def descifrar(self, usuario):

        if not self.cifrado_listo:
            messagebox.showwarning(
                "Missing vault",
                "Encrypt a document first.",
            )
            return

        self.registrar(
            f"[ATTEMPT] {usuario.upper()} requests decryption."
        )

        try:
            datos = abrir_archivo_compartido(
                self.vault,
                self.claves[usuario],
                id_usuario=usuario,
            )

        except DestinatarioNoAutorizado:
            self.registrar(
                f"[DENIED] {usuario.upper()} is not authorized."
            )
            self.estado.set("ACCESS DENIED")
            return

        except Exception as error:
            self.registrar(
                f"[ERROR] {type(error).__name__}: {error}"
            )
            self.estado.set("DECRYPTION ERROR")
            return

        original = self.archivo.read_bytes()

        if datos != original:
            self.registrar(
                "[FAIL] Recovered data differs from original."
            )
            self.estado.set("VERIFICATION FAILED")
            return

        destino = SALIDA / (
            f"recuperado_{usuario}_{self.archivo.name}"
        )
        destino.write_bytes(datos)

        self.registrar(
            f"[GRANTED] {usuario.upper()} decrypted successfully."
        )
        self.registrar("[VERIFIED] Recovered bytes match original.")
        self.registrar(f"[SAVED] {destino.name}")

        try:
            vista = datos.decode("utf-8")[:2000]
        except UnicodeDecodeError:
            vista = (
                "[Binary file recovered successfully]\n"
                f"Size: {len(datos)} bytes\n"
                f"First bytes (hex): {datos[:100].hex(' ')}"
            )

        self.mostrar_datos(
            f"RECOVERED BY {usuario.upper()}\n"
            "------------------------------\n"
            f"File: {destino.name}\n"
            "Verification: MATCH\n\n"
            f"{vista}"
        )

        self.estado.set(f"DECRYPTED BY {usuario.upper()}")

    def manipular(self):

        if not self.cifrado_listo:
            messagebox.showwarning(
                "Missing vault",
                "Encrypt a document first.",
            )
            return

        try:
            contenedor = json.loads(
                self.vault.read_text(encoding="utf-8")
            )

            datos = bytearray(
                base64.b64decode(
                    contenedor["ciphertext"],
                    validate=True,
                )
            )

            if not datos:
                raise ValueError(
                    "Ciphertext is empty."
                )

            antes = datos[0]
            datos[0] ^= 0x01
            despues = datos[0]

            contenedor["ciphertext"] = base64.b64encode(
                datos
            ).decode("ascii")

            self.vault_alterado.write_text(
                json.dumps(contenedor, ensure_ascii=False),
                encoding="utf-8",
            )

            self.alterado_listo = True

            self.mostrar_datos(
                "TAMPERING ATTACK\n"
                "------------------------------\n"
                "A copy of the encrypted container was modified.\n\n"
                f"Original first byte:  {antes:02x}\n"
                f"Modified first byte:  {despues:02x}\n\n"
                f"Modified container:\n{self.vault_alterado.name}\n\n"
                "Next: try decrypting the modified container."
            )

            self.registrar(
                "[ATTACK] One ciphertext byte was modified."
            )
            self.estado.set("CONTAINER TAMPERED")

        except Exception as error:
            self.alterado_listo = False
            self.registrar(
                f"[ERROR] Tampering setup: {error}"
            )

    def probar_manipulacion(self):

        if not self.alterado_listo:
            messagebox.showwarning(
                "Missing modified file",
                "Click TAMPER ENCRYPTED FILE first.",
            )
            return

        self.registrar(
            "[ATTEMPT] Bob decrypts modified container."
        )

        try:
            abrir_archivo_compartido(
                self.vault_alterado,
                self.claves["bob"],
                id_usuario="bob",
            )

        except InvalidTag:
            self.registrar(
                "[BLOCKED] AES-GCM authentication failed."
            )
            self.registrar(
                "[VERIFIED] Tampering was detected."
            )
            self.estado.set("TAMPERING DETECTED")
            messagebox.showinfo(
                "Security verification",
                "AES-GCM detected the modification.\n"
                "The modified document was rejected.",
            )

        except Exception as error:
            self.registrar(
                f"[ERROR] Unexpected: {type(error).__name__}: {error}"
            )
            self.estado.set("UNEXPECTED ERROR")

        else:
            self.registrar(
                "[FAIL] Modified container was accepted!"
            )
            self.estado.set("SECURITY TEST FAILED")


if __name__ == "__main__":
    app = VaultGUI()
    app.mainloop()

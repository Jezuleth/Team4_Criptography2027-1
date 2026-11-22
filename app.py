
import json
import base64
import binascii
import shutil
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox, simpledialog

from vault.integrated_vault import (
    ARCHIVO_ECIES,
    recuperar_identidad,
    enviar_archivo,
    recibir_archivo,
    registrar_identidad_en_gestor,
    revocar_identidad,
)
from vault.key_lifecycle import GestorCicloVida, ErrorCicloVida

BASE = Path("identidades_demo")
USUARIOS = ("alice", "bob")


class VaultDemo:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Digital Document Vault")
        self.root.geometry("800x720")
        self.root.minsize(720, 620)

        self.identidades = {}
        self.passwords = {}
        self.archivo = None
        self.vault = None
        self.interceptado = None
        self.vault_alterado = None
        self.entregado = None
        self.remitente_original = None
        self.destinatario_original = None

        password_estado = simpledialog.askstring(
            "Protección D6",
            "Contraseña del historial de claves (mínimo 12 caracteres):",
            show="*",
            parent=self.root,
        )

        if not password_estado or len(password_estado) < 12:
            raise ValueError("Se requiere una contraseña de al menos 12 caracteres.")

        self.gestor = GestorCicloVida(
            ruta_estado=BASE / "historial_claves.enc",
            password_estado=password_estado,
        )

        frame = ttk.Frame(root, padding=18)
        frame.pack(fill="both", expand=True)

        ttk.Label(
            frame,
            text="SECURE DIGITAL DOCUMENT VAULT",
            font=("Arial", 18, "bold"),
        ).pack(pady=(0, 5))

        ttk.Label(
            frame,
            text="AES-256-GCM | ECIES | Ed25519 | Gestión de claves",
        ).pack(pady=(0, 15))

        intercambio = ttk.LabelFrame(
            frame,
            text="Intercambio seguro de documentos",
            padding=12,
        )
        intercambio.pack(fill="x", pady=5)

        ttk.Label(
            intercambio,
            text="REMITENTE",
        ).grid(row=0, column=0)

        ttk.Label(
            intercambio,
            text="DESTINATARIO",
        ).grid(row=0, column=2)

        self.remitente = ttk.Combobox(
            intercambio,
            values=USUARIOS,
            state="readonly",
            width=18,
        )
        self.remitente.set("alice")
        self.remitente.grid(row=1, column=0, padx=5, pady=8)

        ttk.Label(
            intercambio,
            text="──────  ➜  ──────",
            font=("Arial", 12),
        ).grid(row=1, column=1)

        self.destinatario = ttk.Combobox(
            intercambio,
            values=USUARIOS,
            state="readonly",
            width=18,
        )
        self.destinatario.set("bob")
        self.destinatario.grid(row=1, column=2, padx=5, pady=8)

        intercambio.columnconfigure(0, weight=1)
        intercambio.columnconfigure(1, weight=1)
        intercambio.columnconfigure(2, weight=1)

        documento = ttk.LabelFrame(
            frame,
            text="Documento",
            padding=12,
        )
        documento.pack(fill="x", pady=8)

        self.archivo_label = ttk.Label(
            documento,
            text="Ningún documento seleccionado",
        )
        self.archivo_label.pack(pady=5)

        ttk.Button(
            documento,
            text="Seleccionar documento",
            command=self.seleccionar_archivo,
        ).pack(fill="x")

        ttk.Button(
            documento,
            text="1. Cifrar, firmar y enviar",
            command=self.enviar,
        ).pack(fill="x", pady=(8, 0))

        atacante = ttk.LabelFrame(
            frame,
            text="MALLORY — Simulación de ataque",
            padding=12,
        )
        atacante.pack(fill="x", pady=8)

        acciones_mallory = [
            ("2. Interceptar archivo", self.interceptar),
            ("3. Intentar descifrar", self.ataque_mallory),
            ("4. Modificar archivo", self.manipular),
        ]

        for i, (texto, comando) in enumerate(acciones_mallory):
            ttk.Button(
                atacante,
                text=texto,
                command=comando,
            ).grid(row=0, column=i, padx=4, pady=5, sticky="ew")

            atacante.columnconfigure(i, weight=1)

        recepcion = ttk.LabelFrame(
            frame,
            text="Recepción y verificación",
            padding=12,
        )
        recepcion.pack(fill="x", pady=8)

        ttk.Button(
            recepcion,
            text="5. Entregar archivo al destinatario",
            command=self.entregar,
        ).pack(fill="x", pady=4)

        ttk.Button(
            recepcion,
            text="6. Abrir y verificar documento",
            command=self.descifrar,
        ).pack(fill="x", pady=4)

        gestion_claves = ttk.LabelFrame(
            frame,
            text="Gestión de claves — D6",
            padding=12,
        )
        gestion_claves.pack(fill="x", pady=8)

        ttk.Button(
            gestion_claves,
            text="D6. Revocar clave de Bob",
            command=self.revocar_bob,
        ).pack(fill="x", pady=4)

        registro_frame = ttk.LabelFrame(
            frame,
            text="Registro de seguridad",
            padding=10,
        )
        registro_frame.pack(fill="both", expand=True, pady=8)

        self.registro = tk.Text(
            registro_frame,
            height=12,
            wrap="word",
            font=("Consolas", 10),
            state="disabled",
        )
        self.registro.pack(fill="both", expand=True)

        self.registro.tag_configure(
            "ok",
            foreground="#16803c",
        )
        self.registro.tag_configure(
            "error",
            foreground="#c62828",
        )
        self.registro.tag_configure(
            "info",
            foreground="#175cd3",
        )

        self.estado = ttk.Label(
            frame,
            text="Sistema listo",
            foreground="green",
        )
        self.estado.pack(pady=5)

        self.log(
            "Sistema listo.\n"
            "Selecciona un documento para comenzar.",
            "info",
        )

    def log(self, mensaje, tipo="info"):
        self.registro.config(state="normal")
        self.registro.insert(
            tk.END,
            mensaje + "\n\n",
            tipo,
        )
        self.registro.see(tk.END)
        self.registro.config(state="disabled")

    def actualizar_estado(self, mensaje, correcto=True):
        self.estado.config(
            text=mensaje,
            foreground="green" if correcto else "red",
        )

    def seleccionar_archivo(self):
        ruta = filedialog.askopenfilename(
            title="Seleccionar documento",
        )

        if ruta:
            self.archivo = Path(ruta)
            self.archivo_label.config(
                text=self.archivo.name,
            )
            self.log(
                f"Documento seleccionado: {self.archivo.name}"
            )

    def identidad(self, usuario):
        if usuario in self.identidades:
            return self.identidades[usuario]

        if not (BASE / usuario / ARCHIVO_ECIES).exists():
            raise ValueError(
                f"La clave de {usuario} no está en el repositorio de claves "
                "(fue revocada y eliminada)."
            )

        password = simpledialog.askstring(
            "Desbloquear identidad",
            f"Contraseña de {usuario}:",
            show="*",
            parent=self.root,
        )

        if password is None:
            raise ValueError("Operación cancelada.")

        identidad = recuperar_identidad(
            password,
            BASE / usuario,
        )

        self.identidades[usuario] = identidad
        self.passwords[usuario] = password

        self.log(
            f"Identidad desbloqueada: {usuario}",
            "ok",
        )

        return identidad

    
    def registrar_usuario(self, usuario):
        try:
            self.gestor.obtener_registro(usuario)
            return
        except ErrorCicloVida as error:
            if str(error) != "Registro inexistente.":
                raise

        registrar_identidad_en_gestor(
            usuario,
            BASE / usuario,
            self.passwords[usuario],
            self.gestor,
        )


    def revocar_bob(self):
        try:
            self.identidad("bob")
            self.registrar_usuario("bob")

            if not messagebox.askyesno(
                "Revocar clave",
                "¿Deseas revocar la clave actual de Bob?",
            ):
                return

            eliminada = revocar_identidad(
                "bob",
                BASE / "bob",
                self.gestor,
                "Revocación solicitada durante la demostración D6",
            )

            # La clave privada no debe seguir viva en memoria de la app.
            self.identidades.pop("bob", None)
            self.passwords.pop("bob", None)

            self.log(
                "\n[D6 - REVOCACIÓN]\n"
                "La clave de Bob fue revocada y guardada en disco "
                "(persiste al reiniciar).\n"
                + (
                    "Se eliminó del repositorio de claves.\n"
                    if eliminada
                    else "Ya no estaba en el repositorio de claves.\n"
                )
                + "El sistema bloqueará su uso para descifrar.",
                "error",
            )

            messagebox.showinfo(
                "D6",
                "Clave de Bob revocada correctamente.",
            )

        except Exception as error:
            messagebox.showerror("Error D6", str(error))

    def enviar(self):
        if self.archivo is None:
            messagebox.showwarning(
                "Documento",
                "Primero selecciona un documento.",
            )
            return

        remitente = self.remitente.get()
        destinatario = self.destinatario.get()

        if remitente == destinatario:
            messagebox.showwarning(
                "Usuarios",
                "El remitente y destinatario deben ser diferentes.",
            )
            return

        try:
            self.identidad(remitente)
            identidad_destino = self.identidad(destinatario)

            clave_publica = (
                identidad_destino["clave_ecies"].public_key()
            )

            ruta = filedialog.asksaveasfilename(
                title="Guardar documento cifrado",
                defaultextension=".vault",
                initialfile=self.archivo.stem + ".vault",
                filetypes=[("Archivo Vault", "*.vault")],
            )

            if not ruta:
                return

            enviar_archivo(
                self.archivo,
                ruta,
                {destinatario: clave_publica},
                BASE / remitente,
                self.passwords[remitente],
            )

            self.vault = Path(ruta)
            self.interceptado = None
            self.vault_alterado = None
            self.entregado = None
            self.remitente_original = remitente
            self.destinatario_original = destinatario

            self.log(
                "[ENVÍO SEGURO]\n"
                f"Remitente: {remitente}\n"
                f"Destinatario: {destinatario}\n"
                f"Documento: {self.archivo.name}\n"
                "AES-256-GCM: cifrado realizado.\n"
                "ECIES: clave de archivo protegida.\n"
                "Ed25519: documento firmado.\n"
                f"Contenedor: {self.vault.name}",
                "ok",
            )

            self.actualizar_estado(
                "Documento cifrado y firmado correctamente"
            )

            messagebox.showinfo(
                "Envío seguro",
                "Documento cifrado y firmado correctamente.",
            )

        except Exception as error:
            self.log(
                f"Error al enviar: {error}",
                "error",
            )
            messagebox.showerror("Error", str(error))

    def interceptar(self):
        if self.vault is None:
            messagebox.showwarning(
                "Intercepción",
                "Primero cifra y envía un documento.",
            )
            return

        try:
            copia = self.vault.with_name(
                self.vault.stem + "_interceptado.vault"
            )

            shutil.copyfile(self.vault, copia)

            self.interceptado = copia
            self.vault_alterado = None
            self.entregado = None

            self.log(
                "[INTERCEPCIÓN DE MALLORY]\n"
                "Mallory obtuvo una copia del archivo .vault.\n"
                "El contenido permanece cifrado.\n"
                "No se ha modificado el documento.",
                "info",
            )

            self.actualizar_estado(
                "Mallory interceptó el archivo cifrado"
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def ataque_mallory(self):
        if self.interceptado is None:
            messagebox.showwarning(
                "Ataque",
                "Primero pulsa 'Interceptar archivo'.",
            )
            return

        try:
            self.identidad("mallory")
            identidad_remitente = self.identidad(
                self.remitente_original
            )

            self.registrar_usuario("mallory")

            salida = self.vault.with_name(
                "intento_mallory_" + self.archivo.name
            )

            if salida.exists():
                raise FileExistsError(
                    "El archivo de salida ya existe."
                )

            recibir_archivo(
                self.interceptado,
                salida,
                "mallory",
                BASE / "mallory",
                self.passwords["mallory"],
                identidad_remitente[
                    "clave_firma"
                ].public_key(),
                self.gestor,
            )

            self.log(
                "[ATAQUE DE MALLORY]\n"
                "ADVERTENCIA: Mallory logró descifrar el archivo.",
                "error",
            )

            self.actualizar_estado(
                "Mallory obtuvo acceso",
                False,
            )

            messagebox.showwarning(
                "Advertencia de seguridad",
                "Mallory logró descifrar el documento.",
            )

        except FileExistsError as error:
            self.log(
                f"No se ejecutó la prueba: {error}",
                "error",
            )
            messagebox.showerror(
                "Error de prueba",
                str(error),
            )

        except Exception as error:
            self.log(
                "[ATAQUE DE MALLORY]\n"
                "Mallory intentó descifrar el documento.\n"
                "Resultado: ACCESO RECHAZADO.\n"
                f"Detalle: {error}",
                "error",
            )

            self.actualizar_estado(
                "Acceso no autorizado rechazado"
            )

            messagebox.showwarning(
                "Acceso denegado",
                "Mallory no pudo recuperar el documento.\n\n"
                f"Detalle: {error}",
            )

    def manipular(self):
        if self.interceptado is None:
            messagebox.showwarning(
                "Manipulación",
                "Primero intercepta el archivo.",
            )
            return

        try:
            contenedor = json.loads(
                self.interceptado.read_text(
                    encoding="utf-8"
                )
            )

            def alterar_cifrado(obj):
                if isinstance(obj, dict):
                    for clave, valor in obj.items():
                        if (
                            clave in ("ciphertext", "datos_cifrados")
                            and isinstance(valor, str)
                        ):
                            try:
                                datos = bytearray(
                                    base64.b64decode(
                                        valor,
                                        validate=True,
                                    )
                                )
                            except (ValueError, binascii.Error):
                                continue

                            if datos:
                                datos[0] ^= 1

                                obj[clave] = base64.b64encode(
                                    datos
                                ).decode("ascii")

                                return True

                    for valor in obj.values():
                        if alterar_cifrado(valor):
                            return True

                elif isinstance(obj, list):
                    for valor in obj:
                        if alterar_cifrado(valor):
                            return True

                return False

            if not alterar_cifrado(contenedor):
                raise ValueError(
                    "No se encontró el contenido cifrado "
                    "en el contenedor."
                )

            salida = self.vault.with_name(
                self.vault.stem + "_alterado.vault"
            )

            salida.write_text(
                json.dumps(
                    contenedor,
                    indent=2,
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )

            self.vault_alterado = salida
            self.entregado = None

            self.log(
                "[MANIPULACIÓN DE MALLORY]\n"
                "Mallory modificó un byte del contenido cifrado.\n"
                "Se generó una copia alterada.\n"
                "El archivo original permanece intacto.",
                "error",
            )

            self.actualizar_estado(
                "Archivo manipulado; pendiente de entrega",
                False,
            )

            messagebox.showwarning(
                "Archivo modificado",
                "Mallory modificó el archivo interceptado.\n"
                "Ahora puedes entregarlo al destinatario.",
            )

        except Exception as error:
            self.log(
                f"Error de manipulación: {error}",
                "error",
            )
            messagebox.showerror("Error", str(error))

    def entregar(self):
        if self.vault is None:
            messagebox.showwarning(
                "Entrega",
                "Primero cifra y envía un documento.",
            )
            return

        try:
            fuente = self.vault_alterado or self.vault

            destino = self.vault.with_name(
                self.vault.stem + "_recibido.vault"
            )

            shutil.copyfile(fuente, destino)

            self.entregado = destino

            modificado = self.vault_alterado is not None

            self.log(
                "[ENTREGA AL DESTINATARIO]\n"
                f"Destinatario: {self.destinatario_original}\n"
                + (
                    "Se entregó el archivo modificado."
                    if modificado
                    else "Se entregó el archivo original."
                )
                + "\nPendiente de verificación.",
                "info",
            )

            self.actualizar_estado(
                "Archivo entregado; pendiente de verificación"
            )

        except Exception as error:
            messagebox.showerror("Error", str(error))

    def descifrar(self):
        if self.entregado is None:
            messagebox.showwarning(
                "Recepción",
                "Primero entrega el archivo al destinatario.",
            )
            return

        usuario = self.destinatario_original
        remitente = self.remitente_original

        try:
            self.identidad(usuario)
            identidad_remitente = self.identidad(remitente)

            self.registrar_usuario(usuario)

            salida = filedialog.asksaveasfilename(
                title="Guardar documento recuperado",
                initialfile="recuperado_" + self.archivo.name,
            )

            if not salida:
                return

            recibir_archivo(
                self.entregado,
                salida,
                usuario,
                BASE / usuario,
                self.passwords[usuario],
                identidad_remitente[
                    "clave_firma"
                ].public_key(),
                self.gestor,
            )

            self.log(
                "[VERIFICACIÓN DEL DESTINATARIO]\n"
                f"Usuario: {usuario}\n"
                "Firma digital: VÁLIDA.\n"
                "Integridad: VERIFICADA.\n"
                "Acceso: AUTORIZADO.\n"
                f"Documento recuperado: {salida}",
                "ok",
            )

            self.actualizar_estado(
                "Documento verificado y recuperado"
            )

            messagebox.showinfo(
                "Documento seguro",
                "Firma digital válida.\n"
                "Integridad verificada.\n"
                "Documento recuperado correctamente.",
            )

        except Exception as error:
            self.log(
                "[ALERTA DE SEGURIDAD]\n"
                "El documento recibido fue rechazado.\n"
                "No se pudo verificar o descifrar.\n"
                f"Detalle: {error}",
                "error",
            )

            self.actualizar_estado(
                "Documento rechazado por seguridad",
                False,
            )

            messagebox.showerror(
                "ALERTA DE SEGURIDAD",
                "El documento no pudo verificarse "
                "o descifrarse.\n\n"
                "No se recuperó el contenido.\n\n"
                f"Detalle: {error}",
            )


if __name__ == "__main__":
    root = tk.Tk()
    app = VaultDemo(root)
    root.mainloop()

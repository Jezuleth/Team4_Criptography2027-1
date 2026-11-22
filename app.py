"""Secure Digital Document Vault — aplicación integrada (D2 + D3 + D5 + D6).

Punto de entrada único del sistema: identidades, envío cifrado y firmado,
recepción con verificación, laboratorio de ataques, revocación persistente
y registro de seguridad, todo en una sola ventana.

Diseño inspirado en macOS: barra lateral, tarjetas redondeadas, controles
segmentados, modo claro/oscuro (automático según el sistema) y escalado
para pantallas HiDPI. Solo usa Tkinter (incluido con Python 3.12).

Uso:  python app.py [--identidades CARPETA] [--tema auto|claro|oscuro]
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk
from tkinter import font as tkfont

from cryptography.exceptions import InvalidTag

from vault import ataques
from vault.integrated_vault import (
    ARCHIVO_HISTORIAL,
    DirectorioAlterado,
    abrir_gestor,
    cargar_identidad_publica,
    crear_identidad,
    enviar_archivo_con_claves,
    identificar_remitente,
    listar_identidades,
    recuperar_identidad,
    registrar_claves_en_gestor,
    resumen_identidad,
    revocar_identidad,
    validar_nombre_usuario,
)
from vault.key_lifecycle import ErrorCicloVida, FirmanteRevocado
from vault.keystore import ErrorKeystore, validar_password
from vault.persistencia import escribir_atomico
from vault.shared_container import ContenedorInvalido
from vault.signatures import ErrorFirma
from vault.signed_sharing import descifrar_contenedor_firmado, leer_contenedor

RAIZ = Path(__file__).resolve().parent
USUARIOS_DEMO = ("alice", "bob", "carol", "mallory")

# ==========================================================================
# Apariencia: paletas, escala y tipografía
# ==========================================================================
PALETAS = {
    "claro": dict(
        fondo="#F5F5F7", lateral="#EBEBF0", sel_lateral="#DCDCE2",
        tarjeta="#FFFFFF", borde="#E2E2E7", campo="#FFFFFF",
        texto="#1D1D1F", secundario="#6E6E73", terciario="#AEAEB2",
        acento="#087F91", acento_hover="#066C7C", acento_press="#055A67",
        acento_suave="#E1F4F7", acento_texto="#087F91",
        ok="#248A3D", ok_suave="#E3F5E8", error="#D70015", error_suave="#FDE7EA",
        aviso="#C93400", aviso_suave="#FFF1E0",
        gris="#E8E8ED", gris_hover="#DCDCE1", gris_press="#CFCFD4",
        tooltip="#1D1D1F", tooltip_texto="#FFFFFF",
    ),
    "oscuro": dict(
        fondo="#1C1C1E", lateral="#242426", sel_lateral="#3A3A3C",
        tarjeta="#2C2C2E", borde="#3A3A3C", campo="#1C1C1E",
        texto="#F5F5F7", secundario="#98989D", terciario="#636366",
        acento="#087F91", acento_hover="#0A93A8", acento_press="#066C7C",
        acento_suave="#133D44", acento_texto="#5AC8DC",
        ok="#30D158", ok_suave="#173A22", error="#FF453A", error_suave="#45201E",
        aviso="#FF9F0A", aviso_suave="#44321A",
        gris="#3A3A3C", gris_hover="#48484A", gris_press="#545456",
        tooltip="#48484A", tooltip_texto="#FFFFFF",
    ),
}
ICONOS = {  # color de la "baldosa" de cada sección (estilo Ajustes de macOS)
    "identidades": "#087F91", "enviar": "#007AFF", "recibir": "#34C759",
    "laboratorio": "#FF9500", "actividad": "#8E8E93",
}

T: dict = dict(PALETAS["claro"])  # paleta activa
F: dict = {}                        # fuentes activas
ESCALA = 1.0


def px(valor: float) -> int:
    """Convierte píxeles de diseño a píxeles reales (HiDPI)."""
    return int(round(valor * ESCALA))


def tema_del_sistema() -> str:
    """Detecta el modo oscuro del sistema operativo (mejor esfuerzo)."""
    try:
        if sys.platform == "darwin":
            r = subprocess.run(["defaults", "read", "-g", "AppleInterfaceStyle"],
                               capture_output=True, text=True, timeout=2)
            return "oscuro" if "Dark" in r.stdout else "claro"
        if sys.platform == "win32":
            import winreg
            clave = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            valor, _ = winreg.QueryValueEx(clave, "AppsUseLightTheme")
            return "claro" if valor else "oscuro"
        if ":dark" in os.environ.get("GTK_THEME", "").lower():
            return "oscuro"
        r = subprocess.run(["gsettings", "get", "org.gnome.desktop.interface", "color-scheme"],
                           capture_output=True, text=True, timeout=2)
        return "oscuro" if "dark" in r.stdout.lower() else "claro"
    except Exception:
        return "claro"


def _familia(preferidas, respaldo):
    disponibles = set(tkfont.families())
    return next((f for f in preferidas if f in disponibles), respaldo)


def preparar_fuentes(root):
    """Fuente del sistema en cada plataforma (San Francisco en macOS)."""
    defecto = tkfont.nametofont("TkDefaultFont").actual("family")
    if sys.platform == "darwin":
        familia, base, mono = defecto, 13, _familia(("SF Mono", "Menlo"), "Courier")
    elif sys.platform == "win32":
        familia = _familia(("Segoe UI Variable Text", "Segoe UI"), defecto)
        base, mono = 10, _familia(("Cascadia Mono", "Consolas"), "Courier New")
    else:
        familia = _familia(("Inter", "SF Pro Text", "Cantarell", "Ubuntu",
                            "Noto Sans", "DejaVu Sans"), defecto)
        base = 10
        mono = _familia(("JetBrains Mono", "DejaVu Sans Mono", "Liberation Mono"), "TkFixedFont")
    nueva = lambda tam, peso="normal": tkfont.Font(root=root, family=familia, size=tam, weight=peso)
    F.update(
        titulo=nueva(base + 11, "bold"), h2=nueva(base + 3, "bold"),
        cuerpo=nueva(base), negrita=nueva(base, "bold"), peq=nueva(base - 1),
        etiqueta=nueva(base - 2, "bold"), boton=nueva(base, "bold"),
        icono=nueva(base - 1, "bold"),
        mono=tkfont.Font(root=root, family=mono, size=base - 1),
    )


def recortar(texto, fuente, ancho):
    """Recorta con '…' para que quepa en `ancho` píxeles."""
    if fuente.measure(texto) <= ancho:
        return texto
    while texto and fuente.measure(texto + "…") > ancho:
        texto = texto[:-1]
    return texto + "…"


def corta(huella):
    return f"{huella[:8]}…{huella[-8:]}" if huella else "—"


def mensaje_error(exc) -> str:
    if isinstance(exc, InvalidTag):
        return "La autenticación AES-GCM falló: el contenido fue modificado."
    if isinstance(exc, FileNotFoundError):
        return f"No existe el archivo: {exc.filename or exc}"
    if isinstance(exc, PermissionError):
        return "Permiso denegado al acceder al archivo."
    return str(exc) or exc.__class__.__name__


def ajustar_al_ancho(etiqueta):
    """El texto se reacomoda al ancho real de la etiqueta (diseño adaptable)."""
    etiqueta.bind("<Configure>", lambda e: e.widget.configure(wraplength=max(px(80), e.width - 4)))
    return etiqueta


def _rect_redondeado(canvas, x1, y1, x2, y2, r, **opciones):
    r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
    puntos = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2,
              x2 - r, y2, x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
    return canvas.create_polygon(puntos, smooth=True, splinesteps=24, **opciones)


def _mezclar(origen, destino, t):
    a = [int(origen[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(destino[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(round(x + (y - x) * t) for x, y in zip(a, b))


# ==========================================================================
# Componentes
# ==========================================================================
class Tooltip:
    """Ayuda emergente tras mantener el cursor encima."""

    RETRASO_MS = 550

    def __init__(self, widget, texto):
        self.widget, self.texto = widget, texto
        self._espera = self._ventana = None
        for evento in ("<Leave>", "<ButtonPress>", "<Destroy>"):
            widget.bind(evento, self._ocultar, add="+")
        widget.bind("<Enter>", self._programar, add="+")

    def _programar(self, _e=None):
        self._ocultar()
        self._espera = self.widget.after(self.RETRASO_MS, self._mostrar)

    def _mostrar(self):
        self._espera = None
        v = tk.Toplevel(self.widget)
        v.wm_overrideredirect(True)
        v.configure(bg=T["tooltip"])
        try:
            v.attributes("-topmost", True)
        except tk.TclError:
            pass
        tk.Label(v, text=self.texto, bg=T["tooltip"], fg=T["tooltip_texto"],
                 font=F["peq"], justify="left", wraplength=px(300),
                 padx=px(10), pady=px(6)).pack()
        v.update_idletasks()
        x = self.widget.winfo_rootx() + px(10)
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + px(6)
        if y + v.winfo_reqheight() > self.widget.winfo_screenheight() - px(40):
            y = self.widget.winfo_rooty() - v.winfo_reqheight() - px(6)
        x = max(px(8), min(x, self.widget.winfo_screenwidth() - v.winfo_reqwidth() - px(8)))
        v.wm_geometry(f"+{x}+{y}")
        self._ventana = v

    def _ocultar(self, _e=None):
        if self._espera is not None:
            try:
                self.widget.after_cancel(self._espera)
            except tk.TclError:
                pass
            self._espera = None
        if self._ventana is not None:
            self._ventana.destroy()
            self._ventana = None


class Boton(tk.Canvas):
    """Botón redondeado con transición suave, foco por teclado y tooltip."""

    ESTILOS = {
        "primario": ("acento", "acento_hover", "acento_press", None),
        "secundario": ("gris", "gris_hover", "gris_press", "texto"),
        "peligro": ("error", "error", "error", None),
        "destructivo": ("error_suave", "error_suave", "error_suave", "error"),
        "plano": (None, "gris", "gris_press", "acento_texto"),
    }

    def __init__(self, padre, texto, comando, estilo="secundario", ayuda=None,
                 ancho=None, alto=34, fondo=None, habilitado=True):
        self._fondo = fondo or padre.cget("bg")
        self._fuente = F["boton"]
        natural = self._fuente.measure(texto) + px(32)
        super().__init__(padre, height=px(alto), width=ancho or natural, bg=self._fondo,
                         highlightthickness=0, bd=0, takefocus=1)
        self._texto, self._comando, self._estilo = texto, comando, estilo
        self._habilitado = habilitado
        self._enfocado = False
        self._color = self._colores()[0]
        self._animacion = None
        self.bind("<Configure>", lambda _e: self._dibujar())
        self.bind("<Enter>", lambda _e: self._ir_a(1))
        self.bind("<Leave>", lambda _e: self._ir_a(0))
        self.bind("<ButtonPress-1>", lambda _e: self._ir_a(2, pasos=2))
        self.bind("<ButtonRelease-1>", self._soltar)
        self.bind("<Return>", self._activar)
        self.bind("<space>", self._activar)
        self.bind("<FocusIn>", lambda _e: self._foco(True))
        self.bind("<FocusOut>", lambda _e: self._foco(False))
        self.bind("<Destroy>", self._cancelar_animacion, add="+")
        self.configure(cursor="hand2" if habilitado else "arrow")
        if ayuda:
            Tooltip(self, ayuda)

    def _colores(self):
        if not self._habilitado:
            return [T["gris"]] * 3 + [T["terciario"]]
        base, hover, press, texto = self.ESTILOS[self._estilo]
        if self._estilo in ("peligro", "destructivo"):
            fondo = T[base]
            return [fondo, _mezclar(fondo, T["error"], .15), _mezclar(fondo, T["error"], .3),
                    "#FFFFFF" if self._estilo == "peligro" else T["error"]]
        return [T[base] if base else self._fondo, T[hover], T[press],
                T[texto] if texto else "#FFFFFF"]

    def _dibujar(self):
        self.delete("all")
        ancho, alto = self.winfo_width(), self.winfo_height()
        if ancho <= 1:
            return
        _rect_redondeado(self, 1, 1, ancho - 1, alto - 1, px(9), fill=self._color,
                         outline=T["acento"] if self._enfocado else self._color,
                         width=2 if self._enfocado else 1, tags="forma")
        self.create_text(ancho / 2, alto / 2, fill=self._colores()[3], font=self._fuente,
                         text=recortar(self._texto, self._fuente, ancho - px(16)))

    def _foco(self, valor):
        self._enfocado = valor and self._habilitado
        self._dibujar()

    def _cancelar_animacion(self, _e=None):
        if self._animacion is not None:
            try:
                self.after_cancel(self._animacion)
            except tk.TclError:
                pass
            self._animacion = None

    def _ir_a(self, indice, pasos=6):
        if not self._habilitado:
            return
        self._cancelar_animacion()
        origen, destino = self._color, self._colores()[indice]

        def paso(i):
            if not self.winfo_exists():  # la vista se reconstruyó durante la animación
                return
            t = i / pasos
            self._color = _mezclar(origen, destino, t * t * (3 - 2 * t))
            self.itemconfigure("forma", fill=self._color,
                               outline=T["acento"] if self._enfocado else self._color)
            self._animacion = self.after(14, paso, i + 1) if i < pasos else None

        paso(1)

    def _soltar(self, evento):
        dentro = 0 <= evento.x <= self.winfo_width() and 0 <= evento.y <= self.winfo_height()
        self._ir_a(1 if dentro else 0, pasos=3)
        if dentro:
            self._activar()

    def _activar(self, _e=None):
        if self._habilitado:
            self._comando()


class Segmentado(tk.Canvas):
    """Control segmentado estilo macOS (selección única o múltiple)."""

    def __init__(self, padre, opciones, seleccion, al_cambiar, multiple=False,
                 deshabilitadas=(), alto=32):
        super().__init__(padre, height=px(alto), bg=padre.cget("bg"),
                         highlightthickness=0, bd=0, cursor="hand2")
        self.opciones = list(opciones)
        self.multiple = multiple
        self.seleccion = set(seleccion) if multiple else seleccion
        self.deshabilitadas = set(deshabilitadas)
        self._al_cambiar = al_cambiar
        self.bind("<Configure>", lambda _e: self._dibujar())
        self.bind("<ButtonRelease-1>", self._clic)

    def _activa(self, opcion):
        return opcion in self.seleccion if self.multiple else opcion == self.seleccion

    def _dibujar(self):
        self.delete("all")
        ancho, alto = self.winfo_width(), self.winfo_height()
        if ancho <= 1 or not self.opciones:
            return
        _rect_redondeado(self, 0, 0, ancho, alto, px(9), fill=T["gris"], outline=T["gris"])
        segmento = ancho / len(self.opciones)
        for i, opcion in enumerate(self.opciones):
            x1, x2 = i * segmento, (i + 1) * segmento
            if self._activa(opcion):
                _rect_redondeado(self, x1 + px(3), px(3), x2 - px(3), alto - px(3), px(7),
                                 fill=T["acento"] if self.multiple else T["tarjeta"],
                                 outline=T["borde"])
            color = (T["terciario"] if opcion in self.deshabilitadas else
                     "#FFFFFF" if self.multiple and self._activa(opcion) else T["texto"])
            texto = ("✓ " if self.multiple and self._activa(opcion) else "") + opcion
            self.create_text((x1 + x2) / 2, alto / 2, fill=color, font=F["boton"],
                             text=recortar(texto, F["boton"], segmento - px(12)))

    def _clic(self, evento):
        if not self.opciones or not (0 <= evento.x <= self.winfo_width()):
            return
        indice = int(evento.x // (self.winfo_width() / len(self.opciones)))
        opcion = self.opciones[min(indice, len(self.opciones) - 1)]
        if opcion in self.deshabilitadas:
            return
        if self.multiple:
            self.seleccion ^= {opcion}
        else:
            self.seleccion = opcion
        self._dibujar()
        self._al_cambiar(self.seleccion)


class Tarjeta(tk.Canvas):
    """Contenedor con esquinas redondeadas que se ajusta a su contenido."""

    def __init__(self, padre, titulo=None, relleno=18, expandir=False):
        super().__init__(padre, bg=padre.cget("bg"), highlightthickness=0, bd=0, height=px(60))
        self._p = px(relleno)
        self._expandir = expandir  # True: el contenido ocupa todo el alto disponible
        self.cuerpo = tk.Frame(self, bg=T["tarjeta"])
        self._ventana = self.create_window(self._p, self._p, window=self.cuerpo, anchor="nw")
        self.bind("<Configure>", self._redibujar)
        if not expandir:
            self.cuerpo.bind("<Configure>", self._ajustar_alto)
        if titulo:
            tk.Label(self.cuerpo, text=titulo.upper(), bg=T["tarjeta"], fg=T["secundario"],
                     font=F["etiqueta"], anchor="w").pack(fill="x", pady=(0, px(8)))

    def _ajustar_alto(self, _e=None):
        alto = self.cuerpo.winfo_reqheight() + 2 * self._p
        if int(self.cget("height")) != alto:
            self.configure(height=alto)

    def _redibujar(self, evento):
        self.delete("fondo")
        _rect_redondeado(self, 1, 1, evento.width - 1, evento.height - 1, px(14),
                         fill=T["tarjeta"], outline=T["borde"], tags="fondo")
        self.tag_lower("fondo")
        self.itemconfigure(self._ventana, width=max(1, evento.width - 2 * self._p))
        if self._expandir:
            self.itemconfigure(self._ventana, height=max(1, evento.height - 2 * self._p))


class Pastilla(tk.Canvas):
    """Etiqueta de estado con forma de cápsula."""

    def __init__(self, padre, texto, color, fondo):
        fuente = F["icono"]
        ancho, alto = fuente.measure(texto) + px(20), px(22)
        super().__init__(padre, width=ancho, height=alto, bg=padre.cget("bg"),
                         highlightthickness=0, bd=0)
        _rect_redondeado(self, 0, 0, ancho, alto, alto / 2, fill=fondo, outline=fondo)
        self.create_text(ancho / 2, alto / 2, text=texto, fill=color, font=fuente)


class Rejilla(tk.Frame):
    """Rejilla adaptable: 2 columnas en ventanas anchas, 1 en estrechas."""

    def __init__(self, padre, umbral=720):
        super().__init__(padre, bg=padre.cget("bg"))
        self._hijos, self._columnas, self._umbral = [], 0, px(umbral)
        self.bind("<Configure>", lambda e: self._reordenar(e.width))

    def agregar(self, widget, ancho_completo=False):
        self._hijos.append((widget, ancho_completo))
        self._columnas = 0
        self._reordenar(self.winfo_width())
        return widget

    def _reordenar(self, ancho):
        columnas = 2 if ancho >= self._umbral else 1
        if columnas == self._columnas:
            return
        self._columnas = columnas
        for c in range(2):  # columnas sin uso: sin peso ni grupo uniforme
            usada = c < columnas
            self.columnconfigure(c, weight=1 if usada else 0, uniform="col" if usada else "")
        fila = columna = 0
        for widget, completo in self._hijos:
            if completo and columna:
                fila, columna = fila + 1, 0
            span = columnas if completo else 1
            widget.grid(row=fila, column=columna, columnspan=span, sticky="nsew",
                        padx=px(6), pady=px(6))
            columna += span
            if columna >= columnas:
                fila, columna = fila + 1, 0


class AreaDesplazable(tk.Frame):
    """Área con desplazamiento vertical (rueda en Windows, macOS y Linux)."""

    def __init__(self, padre):
        super().__init__(padre, bg=T["fondo"])
        self.lienzo = tk.Canvas(self, bg=T["fondo"], highlightthickness=0, bd=0)
        self.barra = ttk.Scrollbar(self, orient="vertical", command=self.lienzo.yview,
                                   style="Vault.Vertical.TScrollbar")
        self.interior = tk.Frame(self.lienzo, bg=T["fondo"])
        self._ventana = self.lienzo.create_window(0, 0, window=self.interior, anchor="nw")
        self.lienzo.configure(yscrollcommand=self.barra.set)
        self.lienzo.pack(side="left", fill="both", expand=True)
        self.interior.bind("<Configure>", self._actualizar)
        self.lienzo.bind("<Configure>", self._actualizar)
        self.bind("<Enter>", lambda _e: self._rueda(True))
        self.bind("<Leave>", lambda _e: self._rueda(False))

    def _actualizar(self, _e=None):
        self.lienzo.itemconfigure(self._ventana, width=self.lienzo.winfo_width())
        self.lienzo.configure(scrollregion=self.lienzo.bbox("all"))
        sobra = self.interior.winfo_reqheight() > self.lienzo.winfo_height()
        if sobra and not self.barra.winfo_ismapped():
            self.barra.pack(side="right", fill="y")
        elif not sobra and self.barra.winfo_ismapped():
            self.barra.pack_forget()
            self.lienzo.yview_moveto(0)

    def _rueda(self, activar):
        eventos = ("<MouseWheel>", "<Button-4>", "<Button-5>")
        for evento in eventos:
            if activar:
                self.bind_all(evento, self._desplazar)
            else:
                self.unbind_all(evento)

    def _desplazar(self, evento):
        if not self.barra.winfo_ismapped():
            return
        if evento.num in (4, 5):
            paso = -1 if evento.num == 4 else 1
        elif sys.platform == "darwin":
            paso = -evento.delta
        else:
            paso = -int(evento.delta / 120) or (-1 if evento.delta > 0 else 1)
        self.lienzo.yview_scroll(paso, "units")


class Dialogo(tk.Toplevel):
    """Hoja modal: mensaje, campos opcionales y botones Cancelar/Aceptar.

    `validar(valores)` puede devolver un texto de error que se muestra en la
    misma hoja sin cerrarla. Devuelve los valores (dict) o None si se cancela.
    """

    def __init__(self, padre, titulo, mensaje, campos=(), texto_ok="Aceptar",
                 estilo_ok="primario", validar=None, cancelar=True):
        super().__init__(padre)
        self.resultado = None
        self._validar = validar
        self.title(titulo)
        self.configure(bg=T["tarjeta"])
        self.resizable(False, False)
        self.transient(padre.winfo_toplevel())

        caja = tk.Frame(self, bg=T["tarjeta"])
        caja.pack(fill="both", expand=True, padx=px(24), pady=px(20))
        tk.Label(caja, text=titulo, bg=T["tarjeta"], fg=T["texto"], font=F["h2"],
                 anchor="w").pack(fill="x")
        if mensaje:
            tk.Label(caja, text=mensaje, bg=T["tarjeta"], fg=T["secundario"], font=F["cuerpo"],
                     justify="left", anchor="w", wraplength=px(380)).pack(fill="x", pady=(px(6), 0))

        self._entradas = {}
        for clave, etiqueta, oculto, inicial in campos:
            tk.Label(caja, text=etiqueta, bg=T["tarjeta"], fg=T["secundario"], font=F["peq"],
                     anchor="w").pack(fill="x", pady=(px(12), px(3)))
            entrada = tk.Entry(caja, show="•" if oculto else "", font=F["cuerpo"], relief="flat",
                               bg=T["campo"], fg=T["texto"], insertbackground=T["texto"],
                               highlightthickness=1, highlightbackground=T["borde"],
                               highlightcolor=T["acento"], width=36)
            entrada.insert(0, inicial or "")
            entrada.pack(fill="x", ipady=px(5))
            entrada.bind("<Return>", lambda _e: self._aceptar())
            self._entradas[clave] = (entrada, oculto)

        self._error = tk.Label(caja, text="", bg=T["tarjeta"], fg=T["error"], font=F["peq"],
                               anchor="w", justify="left", wraplength=px(380))
        self._error.pack(fill="x", pady=(px(8), 0))

        botones = tk.Frame(caja, bg=T["tarjeta"])
        botones.pack(fill="x", pady=(px(10), 0))
        if any(oculto for _, oculto in self._entradas.values()):
            self._visible = False
            Boton(botones, "Mostrar", self._alternar, "plano").pack(side="left")
        Boton(botones, texto_ok, self._aceptar, estilo_ok).pack(side="right")
        if cancelar:
            Boton(botones, "Cancelar", self.destroy, "secundario").pack(side="right", padx=(0, px(8)))

        self.bind("<Escape>", lambda _e: self.destroy())
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self._centrar(padre.winfo_toplevel())
        if self._entradas:
            next(iter(self._entradas.values()))[0].focus_set()
        try:
            self.wait_visibility()
            self.grab_set()
        except tk.TclError:
            pass
        self.wait_window()

    def _centrar(self, ventana):
        self.update_idletasks()
        x = ventana.winfo_rootx() + (ventana.winfo_width() - self.winfo_reqwidth()) // 2
        y = ventana.winfo_rooty() + max(px(40), (ventana.winfo_height() - self.winfo_reqheight()) // 3)
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

    def _alternar(self):
        self._visible = not self._visible
        for entrada, oculto in self._entradas.values():
            if oculto:
                entrada.configure(show="" if self._visible else "•")

    def _aceptar(self):
        valores = {clave: e.get() for clave, (e, _) in self._entradas.items()}
        if self._validar is not None:
            self.configure(cursor="watch")
            self.update_idletasks()
            try:
                error = self._validar(valores)
            finally:
                self.configure(cursor="")
            if error:
                self._error.configure(text=error)
                return
        self.resultado = valores
        self.destroy()


# ==========================================================================
# Aplicación
# ==========================================================================
class VaultApp:
    VISTAS = (
        ("identidades", "Identidades", "Llavero y revocación"),
        ("enviar", "Enviar", "Cifrar y firmar"),
        ("recibir", "Recibir", "Verificar y abrir"),
        ("laboratorio", "Laboratorio", "Ataques simulados"),
        ("actividad", "Actividad", "Registro de seguridad"),
    )
    ETAPAS = (
        ("Firma digital",
         "Archivo firmado · firma Ed25519 completa (64 bytes) y válida · "
         "después la llave: signer_id con SHA-256 completo"),
        ("Remitente vigente", "La llave de firma del remitente no está revocada (D6)"),
        ("Tu llave vigente", "Tu clave ECIES es la activa del historial persistente (D6)"),
        ("Descifrado", "Acceso ECIES por destinatario y autenticación AES-256-GCM"),
    )

    def __init__(self, root, base: Path, apariencia="auto"):
        self.root = root
        self.base = base
        self.apariencia = apariencia
        self.gestor = None
        self.sesion: dict[str, dict] = {}   # claves privadas desbloqueadas
        self.eventos: list[tuple] = []
        self.vista = "identidades"
        self.documento: Path | None = None
        self.vault: Path | None = None       # último .vault creado o elegido
        self.remitente = None
        self.destinatarios: set[str] = set()
        self.receptor = None
        self.resultado_recibir = None
        self.resultados_lab: dict[str, dict] = {}

        root.title("Secure Digital Document Vault")
        root.protocol("WM_DELETE_WINDOW", self._salir)
        self._aplicar_tema()
        self._mostrar_desbloqueo()

    # ------------------------------------------------------------------
    # Tema y estructura
    # ------------------------------------------------------------------
    def _aplicar_tema(self):
        nombre = tema_del_sistema() if self.apariencia == "auto" else self.apariencia
        T.clear()
        T.update(PALETAS[nombre])
        self.root.configure(bg=T["fondo"])
        estilo = ttk.Style(self.root)
        estilo.theme_use("clam")
        estilo.layout("Vault.Vertical.TScrollbar", [("Vertical.Scrollbar.trough", {
            "sticky": "ns", "children": [("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
        estilo.configure("Vault.Vertical.TScrollbar", width=px(8), background=T["terciario"],
                         troughcolor=T["fondo"], bordercolor=T["fondo"], relief="flat",
                         lightcolor=T["terciario"], darkcolor=T["terciario"], gripcount=0)
        estilo.map("Vault.Vertical.TScrollbar", background=[("active", T["acento"])])

    def _limpiar_ventana(self):
        for hijo in self.root.winfo_children():
            hijo.destroy()

    def _cambiar_apariencia(self, valor):
        self.apariencia = {"Auto": "auto", "Claro": "claro", "Oscuro": "oscuro"}[valor]
        self._aplicar_tema()
        self._construir_shell()

    def _construir_shell(self):
        self._limpiar_ventana()
        lateral = tk.Frame(self.root, bg=T["lateral"], width=px(220))
        lateral.pack(side="left", fill="y")
        lateral.pack_propagate(False)
        tk.Frame(self.root, bg=T["borde"], width=1).pack(side="left", fill="y")

        tk.Label(lateral, text="Document Vault", bg=T["lateral"], fg=T["texto"], font=F["h2"],
                 anchor="w").pack(fill="x", padx=px(18), pady=(px(22), 0))
        ajustar_al_ancho(tk.Label(lateral, text="ECIES · Ed25519 · AES-GCM", bg=T["lateral"],
                                  fg=T["secundario"], font=F["peq"], anchor="w", justify="left")
                         ).pack(fill="x", padx=px(18), pady=(px(2), px(16)))

        self._items_laterales = {}
        for clave, titulo, subtitulo in self.VISTAS:
            item = tk.Canvas(lateral, height=px(46), bg=T["lateral"], highlightthickness=0,
                             bd=0, cursor="hand2")
            item.pack(fill="x", padx=px(10), pady=px(1))
            item.bind("<Configure>", lambda _e, c=clave: self._dibujar_item(c))
            item.bind("<ButtonRelease-1>", lambda _e, c=clave: self._mostrar(c))
            self._items_laterales[clave] = (item, titulo, subtitulo)

        pie = tk.Frame(lateral, bg=T["lateral"])
        pie.pack(side="bottom", fill="x", padx=px(14), pady=px(16))
        tk.Label(pie, text="APARIENCIA", bg=T["lateral"], fg=T["secundario"], font=F["etiqueta"],
                 anchor="w").pack(fill="x", pady=(0, px(6)))
        actual = {"auto": "Auto", "claro": "Claro", "oscuro": "Oscuro"}[self.apariencia]
        Segmentado(pie, ("Auto", "Claro", "Oscuro"), actual, self._cambiar_apariencia,
                   alto=28).pack(fill="x")
        Boton(pie, "Bloquear sesión", self._bloquear, "secundario",
              ayuda="Olvida las claves privadas desbloqueadas y cierra el historial.",
              ).pack(fill="x", pady=(px(12), 0))

        derecha = tk.Frame(self.root, bg=T["fondo"])
        derecha.pack(side="left", fill="both", expand=True)
        self.estado = tk.Label(derecha, text="", bg=T["fondo"], fg=T["secundario"], font=F["peq"],
                               anchor="w", padx=px(28), pady=px(8))
        self.estado.pack(side="bottom", fill="x")
        tk.Frame(derecha, bg=T["borde"], height=1).pack(side="bottom", fill="x")
        self.contenido = tk.Frame(derecha, bg=T["fondo"])
        self.contenido.pack(fill="both", expand=True)
        if self.eventos:
            self._pintar_estado(*self.eventos[-1])
        self._mostrar(self.vista)

    def _dibujar_item(self, clave):
        item, titulo, subtitulo = self._items_laterales[clave]
        item.delete("all")
        ancho, alto = item.winfo_width(), item.winfo_height()
        if clave == self.vista:
            _rect_redondeado(item, 0, 0, ancho, alto, px(9), fill=T["sel_lateral"],
                             outline=T["sel_lateral"])
        lado = px(26)
        y0 = (alto - lado) / 2
        _rect_redondeado(item, px(8), y0, px(8) + lado, y0 + lado, px(7),
                         fill=ICONOS[clave], outline=ICONOS[clave])
        item.create_text(px(8) + lado / 2, alto / 2, text=titulo[0], fill="#FFFFFF", font=F["icono"])
        item.create_text(px(44), alto / 2 - px(8), text=titulo, anchor="w", fill=T["texto"],
                         font=F["negrita"])
        item.create_text(px(44), alto / 2 + px(9), anchor="w", fill=T["secundario"], font=F["peq"],
                         text=recortar(subtitulo, F["peq"], ancho - px(50)))

    def _cabecera(self, titulo, subtitulo, accion=None):
        cab = tk.Frame(self.contenido, bg=T["fondo"])
        cab.pack(fill="x", padx=px(28), pady=(px(24), px(6)))
        if accion:  # se empaqueta primero para que el texto nunca lo recorte
            texto, comando, estilo = accion
            Boton(cab, texto, lambda: self._seguro(comando), estilo).pack(
                side="right", anchor="n", padx=(px(16), 0), pady=(px(8), 0))
        textos = tk.Frame(cab, bg=T["fondo"])
        textos.pack(side="left", fill="x", expand=True)
        tk.Label(textos, text=titulo, bg=T["fondo"], fg=T["texto"], font=F["titulo"],
                 anchor="w").pack(fill="x")
        ajustar_al_ancho(tk.Label(textos, text=subtitulo, bg=T["fondo"], fg=T["secundario"],
                                  font=F["cuerpo"], anchor="w", justify="left")).pack(fill="x")

    def _mostrar(self, vista):
        self.vista = vista
        for clave in getattr(self, "_items_laterales", {}):
            self._dibujar_item(clave)
        for hijo in self.contenido.winfo_children():
            hijo.destroy()
        getattr(self, f"_vista_{vista}")()

    def _cuerpo(self):
        area = AreaDesplazable(self.contenido)
        area.pack(fill="both", expand=True, padx=px(22), pady=(0, px(10)))
        rejilla = Rejilla(area.interior)
        rejilla.pack(fill="x")
        return rejilla

    # ------------------------------------------------------------------
    # Registro, errores y utilidades
    # ------------------------------------------------------------------
    def registrar(self, texto, tipo="info"):
        evento = (time.strftime("%H:%M:%S"), texto, tipo)
        self.eventos.append(evento)
        if getattr(self, "estado", None) is not None and self.estado.winfo_exists():
            self._pintar_estado(*evento)
        if self.vista == "actividad" and getattr(self, "_texto_log", None) is not None:
            self._escribir_log(evento)

    def _pintar_estado(self, hora, texto, tipo):
        color = {"ok": T["ok"], "error": T["error"], "aviso": T["aviso"]}.get(tipo, T["secundario"])
        self.estado.configure(text=f"●  {hora}   {texto.splitlines()[0]}", fg=color)

    def _alerta(self, titulo, mensaje):
        Dialogo(self.root, titulo, mensaje, texto_ok="Entendido", cancelar=False)

    def _seguro(self, funcion, *args):
        """Ejecuta una acción mostrando cualquier error en una hoja."""
        self.root.configure(cursor="watch")
        self.root.update_idletasks()
        try:
            return funcion(*args)
        except Exception as exc:  # la interfaz nunca debe cerrarse por un error
            self.registrar(f"Error: {mensaje_error(exc)}", "error")
            self._alerta("No se pudo completar", mensaje_error(exc))
        finally:
            self.root.configure(cursor="")

    def _copiar(self, texto, descripcion):
        self.root.clipboard_clear()
        self.root.clipboard_append(texto)
        self.registrar(f"{descripcion} copiada al portapapeles.")

    def _etiqueta(self, padre, texto, estilo="cuerpo", color="texto", **pack):
        etiqueta = tk.Label(padre, text=texto, bg=padre.cget("bg"), fg=T[color], font=F[estilo],
                            anchor="w", justify="left")
        etiqueta.pack(fill="x", **pack)
        return ajustar_al_ancho(etiqueta)

    def _resumenes(self):
        return [resumen_identidad(u, self.base, self.gestor) for u in listar_identidades(self.base)]

    # ------------------------------------------------------------------
    # Desbloqueo del historial (arranque) y de identidades
    # ------------------------------------------------------------------
    def _mostrar_desbloqueo(self):
        self._limpiar_ventana()
        self.estado = None
        nuevo = not (self.base / ARCHIVO_HISTORIAL).exists()
        marco = tk.Frame(self.root, bg=T["fondo"])
        marco.place(relx=.5, rely=.45, anchor="center")
        tarjeta = Tarjeta(marco, relleno=28)
        tarjeta.configure(width=px(440))
        tarjeta.pack()
        c = tarjeta.cuerpo
        lado = px(56)
        icono = tk.Canvas(c, width=lado, height=lado, bg=T["tarjeta"], highlightthickness=0)
        _rect_redondeado(icono, 0, 0, lado, lado, px(14), fill=T["acento"], outline=T["acento"])
        icono.create_text(lado / 2, lado / 2, text="V", fill="#FFFFFF", font=F["titulo"])
        icono.pack(pady=(0, px(12)))
        tk.Label(c, text="Secure Digital Document Vault", bg=T["tarjeta"], fg=T["texto"],
                 font=F["h2"]).pack()
        tk.Label(c, bg=T["tarjeta"], fg=T["secundario"], font=F["cuerpo"], wraplength=px(380),
                 justify="center",
                 text=("Crea la contraseña del historial de claves. Protege, cifrado en disco, "
                       "el estado de cada llave y sus revocaciones." if nuevo else
                       "Introduce la contraseña del historial de claves para continuar.")
                 ).pack(pady=(px(4), px(14)))

        entradas = []
        for etiqueta in (("Contraseña", "Confirmar contraseña") if nuevo else ("Contraseña",)):
            tk.Label(c, text=etiqueta, bg=T["tarjeta"], fg=T["secundario"], font=F["peq"],
                     anchor="w").pack(fill="x", pady=(px(4), px(3)))
            e = tk.Entry(c, show="•", font=F["cuerpo"], relief="flat", bg=T["campo"], fg=T["texto"],
                         insertbackground=T["texto"], highlightthickness=1,
                         highlightbackground=T["borde"], highlightcolor=T["acento"])
            e.pack(fill="x", ipady=px(6))
            entradas.append(e)
        error = tk.Label(c, text="", bg=T["tarjeta"], fg=T["error"], font=F["peq"],
                         wraplength=px(380), justify="center")
        error.pack(pady=(px(8), px(4)))

        def entrar():
            clave = entradas[0].get()
            if nuevo and clave != entradas[1].get():
                error.configure(text="Las contraseñas no coinciden.")
                return
            self.root.configure(cursor="watch")
            self.root.update_idletasks()
            try:
                self.gestor = abrir_gestor(self.base, clave)
            except ErrorCicloVida as exc:
                error.configure(text=mensaje_error(exc))
                entradas[0].delete(0, "end")
                return
            finally:
                self.root.configure(cursor="")
            self.registrar("Historial de claves desbloqueado." if not nuevo else
                           f"Historial de claves creado en {self.base / ARCHIVO_HISTORIAL}.", "ok")
            self._construir_shell()

        Boton(c, "Crear historial" if nuevo else "Desbloquear", entrar, "primario",
              alto=38).pack(fill="x", pady=(px(4), 0))
        tk.Label(c, text=str(self.base), bg=T["tarjeta"], fg=T["terciario"], font=F["peq"],
                 wraplength=px(380)).pack(pady=(px(12), 0))
        for e in entradas:
            e.bind("<Return>", lambda _e: entrar())
        entradas[0].focus_set()

    def _bloquear(self):
        self.sesion.clear()
        self.gestor = None
        self.resultado_recibir = None
        self.resultados_lab.clear()
        self.registrar("Sesión bloqueada: claves privadas descartadas de memoria.")
        self._mostrar_desbloqueo()

    def _salir(self):
        self.sesion.clear()
        self.root.destroy()

    def _desbloquear(self, usuario):
        """Devuelve la identidad privada (pidiendo la contraseña) o None."""
        if usuario in self.sesion:
            return self.sesion[usuario]
        resumen = resumen_identidad(usuario, self.base, self.gestor)
        if not resumen["llaves_en_repositorio"]:
            raise ValueError(f"Las llaves de {usuario} ya no están en el repositorio de llaves "
                             "(identidad revocada o eliminada).")
        recuperada = {}

        def validar(valores):
            try:
                recuperada.update(recuperar_identidad(valores["clave"], self.base / usuario))
            except ErrorKeystore:
                return "Contraseña incorrecta o almacén alterado."
            except (OSError, ValueError) as exc:
                return mensaje_error(exc)
            return None

        dialogo = Dialogo(self.root, f"Desbloquear a {usuario}",
                          "Se descifran sus claves privadas (scrypt + AES-256-GCM) solo en memoria.",
                          campos=(("clave", "Contraseña", True, ""),),
                          texto_ok="Desbloquear", validar=validar)
        if dialogo.resultado is None:
            return None
        registrar_claves_en_gestor(usuario, recuperada, self.gestor)  # rechaza claves revocadas
        self.sesion[usuario] = recuperada
        self.registrar(f"Identidad desbloqueada: {usuario}.", "ok")
        return recuperada

    # ------------------------------------------------------------------
    # Vista: Identidades
    # ------------------------------------------------------------------
    def _vista_identidades(self):
        self._cabecera("Identidades",
                       "Cada identidad tiene una clave ECIES (secp256k1) para recibir y una llave "
                       "Ed25519 para firmar, cifradas en su propio keystore.",
                       ("Nueva identidad", self._nueva_identidad, "primario"))
        rejilla = self._cuerpo()
        resumenes = self._resumenes()
        if not resumenes:
            vacia = rejilla.agregar(Tarjeta(rejilla), ancho_completo=True)
            self._etiqueta(vacia.cuerpo, "Tu llavero está vacío", "h2")
            self._etiqueta(vacia.cuerpo, "Crea las identidades de demostración para recorrer "
                           "el flujo completo: alice y carol (legítimas), bob y mallory.",
                           color="secundario", pady=(px(4), px(12)))
            Boton(vacia.cuerpo, "Crear alice, bob, carol y mallory",
                  lambda: self._seguro(self._crear_demo), "primario").pack(anchor="w")
        for resumen in resumenes:
            rejilla.agregar(self._tarjeta_identidad(rejilla, resumen))

        info = rejilla.agregar(Tarjeta(rejilla, "Revocación persistente"), ancho_completo=True)
        self._etiqueta(info.cuerpo,
                       "Revocar es permanente: se guarda cifrado en historial_claves.enc (escritura "
                       "atómica con fsync), se eliminan ecies.keystore y firma.keystore del "
                       "repositorio de llaves y ambas huellas quedan en la lista de revocación. "
                       "Sobrevive al reinicio y un respaldo restaurado no puede reactivarlas.",
                       color="secundario")

    def _tarjeta_identidad(self, padre, r):
        u = r["usuario"]
        tarjeta = Tarjeta(padre)
        fila = tk.Frame(tarjeta.cuerpo, bg=T["tarjeta"])
        fila.pack(fill="x")
        lado = px(40)
        tono = "#%s" % hashlib.sha256(u.encode()).hexdigest()[:6]
        avatar = tk.Canvas(fila, width=lado, height=lado, bg=T["tarjeta"], highlightthickness=0)
        color = _mezclar(tono, T["acento"], .55)
        avatar.create_oval(1, 1, lado - 1, lado - 1, fill=color, outline=color)
        avatar.create_text(lado / 2, lado / 2, text=u[0].upper(), fill="#FFFFFF", font=F["h2"])
        avatar.pack(side="left", anchor="n", padx=(0, px(12)))

        datos = tk.Frame(fila, bg=T["tarjeta"])
        datos.pack(side="left", fill="x", expand=True)
        titulo = tk.Frame(datos, bg=T["tarjeta"])
        titulo.pack(fill="x")
        tk.Label(titulo, text=u, bg=T["tarjeta"], fg=T["texto"], font=F["h2"]).pack(side="left")
        estados = {"activa": ("Activa", "ok"), "revocada": ("Revocada", "error"),
                   "sin registrar": ("Sin registrar", "aviso"), "rotada": ("Rotada", "secundario")}
        texto, tono = estados.get(r["estado"], (r["estado"], "secundario"))
        Pastilla(titulo, texto, T[tono], T.get(f"{tono}_suave", T["gris"])).pack(side="left", padx=(px(8), 0))
        if u in self.sesion:
            Pastilla(titulo, "Desbloqueada", T["acento_texto"], T["acento_suave"]).pack(
                side="left", padx=(px(6), 0))

        for nombre, huella in (("ECIES", r["huella_ecies"]), ("Firma", r["signer_id"])):
            etiqueta = tk.Label(datos, text=f"{nombre:<6} {corta(huella)}", bg=T["tarjeta"],
                                fg=T["secundario"], font=F["mono"], anchor="w",
                                cursor="hand2" if huella else "")
            etiqueta.pack(fill="x", pady=(px(3), 0))
            if huella:
                etiqueta.bind("<Button-1>", lambda _e, h=huella, n=nombre:
                              self._copiar(h, f"Huella {n} de {u}"))
                Tooltip(etiqueta, f"SHA-256 completo (clic para copiar):\n{huella}")
        if r["estado"] == "revocada" and r["motivo"]:
            self._etiqueta(datos, f"Motivo: {r['motivo']}", "peq", "error", pady=(px(4), 0))
        if not r["llaves_en_repositorio"]:
            self._etiqueta(datos, "Llaves retiradas del repositorio.", "peq", "secundario")
        if r["error_directorio"]:
            self._etiqueta(datos, r["error_directorio"], "peq", "aviso", pady=(px(4), 0))

        acciones = tk.Frame(tarjeta.cuerpo, bg=T["tarjeta"])
        acciones.pack(fill="x", pady=(px(12), 0))
        revocada = r["estado"] == "revocada"
        if u in self.sesion:
            Boton(acciones, "Bloquear", lambda: self._olvidar(u), "secundario").pack(side="left")
        else:
            Boton(acciones, "Desbloquear", lambda: self._seguro(self._desbloquear_y_refrescar, u),
                  "secundario", habilitado=r["llaves_en_repositorio"] and not revocada).pack(side="left")
        Boton(acciones, "Revocar", lambda: self._seguro(self._revocar, u), "destructivo",
              habilitado=not revocada,
              ayuda="Revoca de forma permanente las dos llaves y las retira del repositorio.",
              ).pack(side="right")
        return tarjeta

    def _desbloquear_y_refrescar(self, usuario):
        if self._desbloquear(usuario):
            self._mostrar("identidades")

    def _olvidar(self, usuario):
        self.sesion.pop(usuario, None)
        self.registrar(f"Claves de {usuario} descartadas de memoria.")
        self._mostrar("identidades")

    def _validar_alta(self, valores, con_usuario=True):
        try:
            if con_usuario:
                validar_nombre_usuario(valores["usuario"])
                if valores["usuario"] in listar_identidades(self.base):
                    return "Ya existe una identidad con ese nombre."
            validar_password(valores["clave"])
        except (ValueError, ErrorKeystore) as exc:
            return str(exc)
        if valores["clave"] != valores["confirmar"]:
            return "Las contraseñas no coinciden."
        return None

    def _nueva_identidad(self):
        d = Dialogo(self.root, "Nueva identidad",
                    "Se generan una clave ECIES secp256k1 y una llave Ed25519, protegidas con "
                    "esta contraseña (mínimo 12 caracteres).",
                    campos=(("usuario", "Nombre (minúsculas, sin espacios)", False, ""),
                            ("clave", "Contraseña", True, ""),
                            ("confirmar", "Confirmar contraseña", True, "")),
                    texto_ok="Crear", validar=self._validar_alta)
        if d.resultado:
            u = d.resultado["usuario"]
            identidad = crear_identidad(u, d.resultado["clave"], self.base / u, self.gestor)
            self.registrar(f"Identidad creada: {u}  ·  firma {corta(identidad['signer_id'])}", "ok")
            self._mostrar("identidades")

    def _crear_demo(self):
        d = Dialogo(self.root, "Identidades de demostración",
                    "Una sola contraseña para alice, bob, carol y mallory (solo para la demo).",
                    campos=(("clave", "Contraseña", True, ""),
                            ("confirmar", "Confirmar contraseña", True, "")),
                    texto_ok="Crear", validar=lambda v: self._validar_alta(v, con_usuario=False))
        if not d.resultado:
            return
        existentes = set(listar_identidades(self.base))
        for u in USUARIOS_DEMO:
            if u not in existentes:
                crear_identidad(u, d.resultado["clave"], self.base / u, self.gestor)
                self.registrar(f"Identidad creada: {u}.", "ok")
        self._mostrar("identidades")

    def _revocar(self, usuario):
        if not self.gestor.existe_registro(usuario) and not self._desbloquear(usuario):
            return  # una identidad antigua se registra al desbloquearla una vez
        d = Dialogo(self.root, f"Revocar a {usuario}",
                    f"Esta acción es permanente. Se guardará en disco, se eliminarán las llaves de "
                    f"{usuario} del repositorio, nadie podrá cifrar para {usuario} y los archivos "
                    f"firmados por {usuario} dejarán de abrirse.",
                    campos=(("motivo", "Motivo", False, "Compromiso de clave"),),
                    texto_ok="Revocar", estilo_ok="peligro",
                    validar=lambda v: None if v["motivo"].strip() else "Indica un motivo.")
        if not d.resultado:
            return
        eliminadas = revocar_identidad(usuario, self.base / usuario, self.gestor,
                                       d.resultado["motivo"].strip())
        self.sesion.pop(usuario, None)
        self.destinatarios.discard(usuario)
        self.registrar(
            f"REVOCACIÓN de {usuario}: guardada en disco (persiste al reiniciar). "
            + ("Llaves eliminadas del repositorio." if eliminadas else
               "Sus llaves ya no estaban en el repositorio."), "error")
        self._mostrar("identidades")

    # ------------------------------------------------------------------
    # Vista: Enviar
    # ------------------------------------------------------------------
    def _vista_enviar(self):
        self._cabecera("Enviar", "Cifra una sola vez con AES-256-GCM, envuelve la clave del archivo "
                       "con ECIES para cada destinatario y firma todo el contenedor con Ed25519.")
        rejilla = self._cuerpo()
        resumenes = self._resumenes()
        # Remitente: necesita sus llaves (una identidad antigua se registra al desbloquearla).
        activos = [r["usuario"] for r in resumenes
                   if r["estado"] in ("activa", "sin registrar") and r["llaves_en_repositorio"]]
        # Destinatarios: solo claves públicas ACTIVAS en el historial y con directorio íntegro.
        posibles_dest = [r["usuario"] for r in resumenes
                         if r["estado"] == "activa" and not r["error_directorio"]]
        if self.remitente not in activos:
            self.remitente = activos[0] if activos else None
        self.destinatarios &= set(posibles_dest) - {self.remitente}

        doc = rejilla.agregar(Tarjeta(rejilla, "1 · Documento"))
        if self.documento:
            self._etiqueta(doc.cuerpo, self.documento.name, "negrita")
            self._etiqueta(doc.cuerpo, f"{self.documento.stat().st_size:,} bytes · "
                           f"{self.documento.parent}" if self.documento.exists() else
                           "El archivo ya no existe.", "peq", "secundario")
        else:
            self._etiqueta(doc.cuerpo, "Ningún documento seleccionado.", color="secundario")
        Boton(doc.cuerpo, "Elegir documento…", self._elegir_documento, "secundario",
              ayuda="El original no se modifica ni se envía a ningún servidor.").pack(
            anchor="w", pady=(px(10), 0))

        rem = rejilla.agregar(Tarjeta(rejilla, "2 · Remitente (firma)"))
        if activos:
            Segmentado(rem.cuerpo, activos, self.remitente,
                       lambda v: (setattr(self, "remitente", v), self._mostrar("enviar"))).pack(fill="x")
            self._etiqueta(rem.cuerpo, "Se pedirá su contraseña para usar su llave de firma.",
                           "peq", "secundario", pady=(px(8), 0))
        else:
            self._etiqueta(rem.cuerpo, "No hay identidades activas. Créalas en Identidades.",
                           color="secundario")

        dest = rejilla.agregar(Tarjeta(rejilla, "3 · Destinatarios (ECIES)"), ancho_completo=True)
        posibles = [u for u in posibles_dest if u != self.remitente]
        if posibles:
            Segmentado(dest.cuerpo, posibles, self.destinatarios,
                       lambda v: setattr(self, "destinatarios", set(v)), multiple=True).pack(fill="x")
            self._etiqueta(dest.cuerpo, "Selecciona uno o varios. Las identidades revocadas no "
                           "aparecen: no se puede cifrar para ellas.", "peq", "secundario",
                           pady=(px(8), 0))
        else:
            self._etiqueta(dest.cuerpo, "Se necesita al menos otra identidad activa.",
                           color="secundario")

        accion = rejilla.agregar(Tarjeta(rejilla, "4 · Cifrar y firmar"), ancho_completo=True)
        self._etiqueta(accion.cuerpo, "Se generará un archivo .vault autenticado: cualquier "
                       "cambio en el contenido, los metadatos, la lista de destinatarios o la "
                       "firma impedirá abrirlo.", color="secundario")
        Boton(accion.cuerpo, "Cifrar, firmar y guardar…", lambda: self._seguro(self._enviar),
              "primario", alto=38).pack(anchor="w", pady=(px(12), 0))
        if self.vault:
            self._etiqueta(accion.cuerpo, f"Último .vault: {self.vault}", "peq", "acento_texto",
                           pady=(px(10), 0))

    def _elegir_documento(self):
        ruta = filedialog.askopenfilename(title="Elegir documento", parent=self.root)
        if ruta:
            self.documento = Path(ruta)
            self.registrar(f"Documento seleccionado: {self.documento.name}")
            self._mostrar("enviar")

    def _enviar(self):
        if not self.documento or not self.documento.is_file():
            raise ValueError("Primero elige un documento.")
        if not self.remitente:
            raise ValueError("Elige un remitente.")
        if not self.destinatarios:
            raise ValueError("Elige al menos un destinatario.")
        identidad = self._desbloquear(self.remitente)
        if identidad is None:
            return
        publicas = {u: cargar_identidad_publica(self.base / u, self.gestor)["clave_publica_ecies"]
                    for u in sorted(self.destinatarios)}
        ruta = filedialog.asksaveasfilename(
            title="Guardar documento cifrado", parent=self.root, defaultextension=".vault",
            initialdir=self.documento.parent, initialfile=self.documento.stem + ".vault",
            filetypes=[("Archivo Vault", "*.vault")])
        if not ruta:
            return
        enviar_archivo_con_claves(self.documento, ruta, publicas, identidad["clave_firma"], self.gestor)
        self.vault = Path(ruta)
        self.resultado_recibir = None
        self.resultados_lab.clear()
        self.registrar(f"ENVÍO: {self.documento.name} cifrado (AES-256-GCM) para "
                       f"{', '.join(sorted(publicas))} y firmado por {self.remitente} (Ed25519) "
                       f"→ {self.vault.name}", "ok")
        self._alerta("Documento protegido",
                     f"{self.vault.name} está cifrado para {', '.join(sorted(publicas))} "
                     f"y firmado por {self.remitente}.")
        self._mostrar("enviar")

    # ------------------------------------------------------------------
    # Verificación compartida por Recibir y Laboratorio
    # ------------------------------------------------------------------
    def _verificar(self, contenedor, usuario, clave_firmante=None):
        """Ejecuta el flujo REAL de la biblioteca y traduce el resultado a etapas.

        No reimplementa ninguna comprobación: llama a identificar_remitente y a
        descifrar_contenedor_firmado (firma -> llave -> revocación -> descifrado).
        """
        try:
            if clave_firmante is None:
                clave_firmante = identificar_remitente(
                    contenedor, self.base, self.gestor)["clave_publica_firma"]
            datos = descifrar_contenedor_firmado(
                contenedor, self.sesion[usuario]["clave_ecies"], usuario,
                clave_firmante, self.gestor)
            return {"estados": ["ok"] * 4, "datos": datos, "error": None, "etapa": None}
        except (ErrorFirma, DirectorioAlterado, ContenedorInvalido) as exc:
            etapa, error = 0, exc
        except FirmanteRevocado as exc:
            etapa, error = 1, exc
        except ErrorCicloVida as exc:
            etapa, error = 2, exc
        except Exception as exc:  # DestinatarioNoAutorizado, ErrorDeAcceso, InvalidTag...
            etapa, error = 3, exc
        estados = ["ok"] * etapa + ["error"] + ["omitida"] * (3 - etapa)
        return {"estados": estados, "datos": None, "error": mensaje_error(error), "etapa": etapa}

    def _pintar_etapas(self, padre, resultado):
        for i, (titulo, detalle) in enumerate(self.ETAPAS):
            estado = resultado["estados"][i] if resultado else "pendiente"
            fila = tk.Frame(padre, bg=T["tarjeta"])
            fila.pack(fill="x", pady=px(5))
            lado = px(24)
            marca = tk.Canvas(fila, width=lado, height=lado, bg=T["tarjeta"], highlightthickness=0)
            color, simbolo = {"ok": (T["ok"], "✓"), "error": (T["error"], "✕"),
                              "omitida": (T["gris"], "–")}.get(estado, (T["gris"], str(i + 1)))
            marca.create_oval(1, 1, lado - 1, lado - 1, fill=color, outline=color)
            marca.create_text(lado / 2, lado / 2, text=simbolo, font=F["icono"],
                              fill="#FFFFFF" if estado in ("ok", "error") else T["secundario"])
            marca.pack(side="left", anchor="n", padx=(0, px(10)))
            textos = tk.Frame(fila, bg=T["tarjeta"])
            textos.pack(side="left", fill="x", expand=True)
            self._etiqueta(textos, titulo, "negrita",
                           "terciario" if estado == "omitida" else "texto")
            self._etiqueta(textos, resultado["error"] if estado == "error" else detalle, "peq",
                           "error" if estado == "error" else "secundario")

    # ------------------------------------------------------------------
    # Vista: Recibir
    # ------------------------------------------------------------------
    def _vista_recibir(self):
        self._cabecera("Recibir", "Antes de descifrar se verifica SIEMPRE la firma completa, "
                       "después la llave del firmante y el estado de revocación. "
                       "Un archivo sin firma nunca se descifra.")
        rejilla = self._cuerpo()
        archivo = rejilla.agregar(Tarjeta(rejilla, "Archivo .vault"))
        contenedor, receptores = None, []
        if self.vault:
            self._etiqueta(archivo.cuerpo, self.vault.name, "negrita")
            try:
                contenedor = leer_contenedor(self.vault)
                receptores = [d.get("id") for d in contenedor.get("recipients", [])
                              if isinstance(d, dict) and isinstance(d.get("id"), str)]
                firmado = isinstance(contenedor.get("signature"), str)
                self._etiqueta(archivo.cuerpo,
                               f"Destinatarios declarados: {', '.join(receptores) or '—'}",
                               "peq", "secundario", pady=(px(4), 0))
                self._etiqueta(archivo.cuerpo, "Contiene firma (aún sin verificar)." if firmado else
                               "SIN FIRMA: el sistema no permitirá descifrarlo.", "peq",
                               "secundario" if firmado else "error")
            except ErrorFirma as exc:
                self._etiqueta(archivo.cuerpo, mensaje_error(exc), "peq", "error")
        else:
            self._etiqueta(archivo.cuerpo, "Ningún archivo seleccionado.", color="secundario")
        Boton(archivo.cuerpo, "Elegir .vault…", self._elegir_vault, "secundario").pack(
            anchor="w", pady=(px(10), 0))

        como = rejilla.agregar(Tarjeta(rejilla, "Abrir como"))
        locales = listar_identidades(self.base)
        opciones = [u for u in receptores if u in locales] or locales
        if self.receptor not in opciones:
            self.receptor = opciones[0] if opciones else None
        if opciones:
            Segmentado(como.cuerpo, opciones, self.receptor,
                       lambda v: (setattr(self, "receptor", v), setattr(self, "resultado_recibir", None),
                                  self._mostrar("recibir"))).pack(fill="x")
            self._etiqueta(como.cuerpo, "El remitente se identifica por su signer_id en el "
                           "directorio local de claves públicas.", "peq", "secundario",
                           pady=(px(8), 0))
        else:
            self._etiqueta(como.cuerpo, "No hay identidades locales.", color="secundario")

        verif = rejilla.agregar(Tarjeta(rejilla, "Verificación"), ancho_completo=True)
        self._pintar_etapas(verif.cuerpo, self.resultado_recibir)
        Boton(verif.cuerpo, "Verificar y abrir…", lambda: self._seguro(self._recibir, contenedor),
              "primario", alto=38, habilitado=contenedor is not None and bool(opciones)).pack(
            anchor="w", pady=(px(12), 0))

    def _elegir_vault(self):
        ruta = filedialog.askopenfilename(title="Elegir archivo .vault", parent=self.root,
                                          filetypes=[("Archivo Vault", "*.vault"), ("Todos", "*")])
        if ruta:
            self.vault = Path(ruta)
            self.resultado_recibir = None
            self.resultados_lab.clear()
            self.registrar(f"Archivo seleccionado: {self.vault.name}")
            self._mostrar(self.vista)

    def _recibir(self, contenedor):
        if self._desbloquear(self.receptor) is None:
            return
        resultado = self._verificar(contenedor, self.receptor)
        self.resultado_recibir = resultado
        if resultado["datos"] is None:
            self.registrar(f"RECHAZADO ({self.ETAPAS[resultado['etapa']][0]}): "
                           f"{resultado['error']} No se escribió ningún archivo.", "error")
            self._mostrar("recibir")
            return
        nombre = Path(str(contenedor["header"].get("nombre_archivo", "documento"))).name
        self._mostrar("recibir")
        ruta = filedialog.asksaveasfilename(title="Guardar documento recuperado", parent=self.root,
                                            initialdir=self.vault.parent,
                                            initialfile=f"recuperado_{nombre}")
        if not ruta:
            self.registrar("Verificación correcta; guardado cancelado por el usuario.", "aviso")
            return
        escribir_atomico(ruta, resultado["datos"], modo=0o600)
        self.registrar(f"RECIBIDO por {self.receptor}: firma válida, llaves vigentes, "
                       f"integridad verificada → {Path(ruta).name}", "ok")

    # ------------------------------------------------------------------
    # Vista: Laboratorio
    # ------------------------------------------------------------------
    def _vista_laboratorio(self):
        self._cabecera("Laboratorio", "Mallory ataca una copia del último .vault en memoria. "
                       "El archivo original no cambia. Todos los ataques deben quedar bloqueados.",
                       ("Ejecutar todos", self._ejecutar_todos, "primario"))
        rejilla = self._cuerpo()
        objetivo = rejilla.agregar(Tarjeta(rejilla, "Objetivo"), ancho_completo=True)
        if self.vault:
            self._etiqueta(objetivo.cuerpo, self.vault.name, "negrita")
            self._etiqueta(objetivo.cuerpo, "La víctima abre las copias alteradas como el "
                           "primer destinatario local; se pedirá su contraseña una vez.",
                           "peq", "secundario")
        else:
            self._etiqueta(objetivo.cuerpo, "Primero crea un .vault en Enviar o elige uno.",
                           color="secundario")
        Boton(objetivo.cuerpo, "Elegir .vault…", self._elegir_vault, "secundario").pack(
            anchor="w", pady=(px(10), 0))

        casos = [(c, t, d) for c, t, d, _ in ataques.CATALOGO]
        casos.append(("mallory", "Mallory intenta abrirlo",
                      "Firma auténtica, pero Mallory no es destinataria: ECIES le niega el acceso."))
        for clave, titulo, descripcion in casos:
            t = rejilla.agregar(Tarjeta(rejilla))
            cab = tk.Frame(t.cuerpo, bg=T["tarjeta"])
            cab.pack(fill="x")
            tk.Label(cab, text=titulo, bg=T["tarjeta"], fg=T["texto"], font=F["negrita"]).pack(side="left")
            res = self.resultados_lab.get(clave)
            if res:
                if res["datos"] is None:
                    Pastilla(cab, f"Bloqueado · {self.ETAPAS[res['etapa']][0]}", T["ok"],
                             T["ok_suave"]).pack(side="right")
                else:
                    Pastilla(cab, "¡Aceptado!", T["error"], T["error_suave"]).pack(side="right")
            self._etiqueta(t.cuerpo, descripcion, "peq", "secundario", pady=(px(4), 0))
            if res and res["error"]:
                self._etiqueta(t.cuerpo, res["error"], "peq", "texto", pady=(px(4), 0))
            Boton(t.cuerpo, "Ejecutar", lambda c=clave: self._seguro(self._atacar, c), "secundario",
                  habilitado=self.vault is not None).pack(anchor="w", pady=(px(10), 0))

    def _preparar_ataque(self):
        if not self.vault:
            raise ValueError("Primero crea o elige un .vault.")
        original = leer_contenedor(self.vault)
        remitente = identificar_remitente(original, self.base, self.gestor)
        locales = set(listar_identidades(self.base))
        victima = next((d["id"] for d in original["recipients"] if d["id"] in locales), None)
        if victima is None:
            raise ValueError("Ningún destinatario del archivo es una identidad local.")
        return original, remitente, victima

    def _atacar(self, clave, preparado=None):
        original, remitente, victima = preparado or self._preparar_ataque()
        if clave == "mallory":
            if "mallory" not in listar_identidades(self.base):
                raise ValueError("Crea la identidad 'mallory' en Identidades.")
            usuario, contenedor = "mallory", original
        else:
            usuario, contenedor = victima, ataques.ATAQUES[clave](original)
        if self._desbloquear(usuario) is None:
            return False
        resultado = self._verificar(contenedor, usuario, remitente["clave_publica_firma"])
        self.resultados_lab[clave] = resultado
        bloqueado = resultado["datos"] is None
        self.registrar(f"ATAQUE «{clave}»: " + (
            f"bloqueado en «{self.ETAPAS[resultado['etapa']][0]}» — {resultado['error']}"
            if bloqueado else "¡ACEPTADO! (fallo de seguridad)"), "ok" if bloqueado else "error")
        if preparado is None:
            self._mostrar("laboratorio")
        return True

    def _ejecutar_todos(self):
        preparado = self._preparar_ataque()
        claves = [c for c, *_ in ataques.CATALOGO]
        if "mallory" in listar_identidades(self.base):
            claves.append("mallory")
        for clave in claves:
            if not self._atacar(clave, preparado):
                break
        self._mostrar("laboratorio")

    # ------------------------------------------------------------------
    # Vista: Actividad
    # ------------------------------------------------------------------
    def _vista_actividad(self):
        self._cabecera("Actividad", "Registro de seguridad de esta sesión.",
                       ("Exportar…", self._exportar_log, "secundario"))
        marco = Tarjeta(self.contenido, relleno=14, expandir=True)
        marco.pack(fill="both", expand=True, padx=px(28), pady=(px(6), px(16)))
        texto = tk.Text(marco.cuerpo, wrap="word", font=F["mono"], bg=T["tarjeta"], fg=T["texto"],
                        relief="flat", bd=0, highlightthickness=0, padx=px(4), pady=px(4),
                        spacing3=px(4))
        barra = ttk.Scrollbar(marco.cuerpo, orient="vertical", command=texto.yview,
                              style="Vault.Vertical.TScrollbar")
        texto.configure(yscrollcommand=barra.set)
        barra.pack(side="right", fill="y")
        texto.pack(side="left", fill="both", expand=True)
        for tipo in ("ok", "error", "aviso"):
            texto.tag_configure(tipo, foreground=T[tipo])
        texto.tag_configure("hora", foreground=T["terciario"])
        self._texto_log = texto
        texto.bind("<Destroy>", lambda _e: setattr(self, "_texto_log", None))
        if not self.eventos:
            texto.insert("end", "Sin actividad todavía.\n", "hora")
        for evento in self.eventos:
            self._escribir_log(evento)
        texto.configure(state="disabled")

    def _escribir_log(self, evento):
        hora, mensaje, tipo = evento
        self._texto_log.configure(state="normal")
        self._texto_log.insert("end", f"{hora}  ", "hora")
        self._texto_log.insert("end", mensaje + "\n", tipo)
        self._texto_log.see("end")
        self._texto_log.configure(state="disabled")

    def _exportar_log(self):
        ruta = filedialog.asksaveasfilename(title="Exportar registro", parent=self.root,
                                            defaultextension=".txt",
                                            initialfile="registro_vault.txt")
        if ruta:
            lineas = "".join(f"{h}  [{t.upper()}] {m}\n" for h, m, t in self.eventos)
            escribir_atomico(ruta, lineas.encode("utf-8"), modo=0o644)
            self.registrar(f"Registro exportado a {Path(ruta).name}.", "ok")


# ==========================================================================
# Arranque
# ==========================================================================
def _activar_dpi_windows():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main(argv=None):
    global ESCALA
    parser = argparse.ArgumentParser(description="Secure Digital Document Vault")
    parser.add_argument("--identidades", type=Path,
                        default=Path(os.environ.get("VAULT_IDENTIDADES", RAIZ / "identidades_demo")),
                        help="carpeta del repositorio de llaves (por defecto identidades_demo/)")
    parser.add_argument("--tema", choices=("auto", "claro", "oscuro"),
                        default=os.environ.get("VAULT_TEMA", "auto"))
    args = parser.parse_args(argv)

    _activar_dpi_windows()
    root = tk.Tk()
    if sys.platform != "darwin":  # macOS ya trabaja en puntos (Retina)
        ESCALA = min(3.0, max(1.0, root.winfo_fpixels("1i") / 96))
    preparar_fuentes(root)

    ancho_pantalla, alto_pantalla = root.winfo_screenwidth(), root.winfo_screenheight()
    ancho = min(px(1180), int(ancho_pantalla * .9))
    alto = min(px(800), int(alto_pantalla * .88))
    root.geometry(f"{ancho}x{alto}+{(ancho_pantalla - ancho) // 2}+{max(0, (alto_pantalla - alto) // 3)}")
    root.minsize(min(px(780), ancho_pantalla - 40), min(px(560), alto_pantalla - 80))

    VaultApp(root, args.identidades.resolve(), args.tema)
    root.mainloop()


if __name__ == "__main__":
    main()

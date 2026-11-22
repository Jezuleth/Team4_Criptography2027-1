"""Demo final del sistema integrado (D2 + D3 + D5 + D6), en consola.

Recorre el flujo completo con los mismos módulos que usa app.py y comprueba
cada resultado esperado. No necesita interfaz gráfica: funciona por SSH,
en CI o en cualquier arquitectura.

    python demo_final.py                    # carpeta temporal, se borra al final
    python demo_final.py --carpeta salida   # conserva los archivos generados

Código de salida 0 si todas las comprobaciones pasan, 1 si alguna falla.
"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
from pathlib import Path

from vault import ataques
from vault.integrated_vault import (
    ARCHIVO_ECIES,
    ARCHIVO_FIRMA,
    abrir_gestor,
    cargar_identidad_publica,
    crear_identidad,
    enviar_archivo_con_claves,
    identificar_remitente,
    recuperar_identidad,
    resumen_identidad,
    revocar_identidad,
)
from vault.key_lifecycle import ErrorCicloVida, FirmanteRevocado
from vault.public_key import DestinatarioNoAutorizado
from vault.sharing import compartir_archivo
from vault.signatures import ErrorFirma
from vault.signed_sharing import descifrar_contenedor_firmado, leer_contenedor

# Contraseñas fijas SOLO para la demo automática (nunca en uso real).
PASSWORD = "demo-final-equipo-4"
HISTORIAL = "historial-demo-final-4"
MENSAJE = "Documento confidencial · Equipo 4 · Criptografía UNAM 2027-1".encode()


class Demo:
    def __init__(self, carpeta: Path, imprimir=print):
        self.carpeta = carpeta
        self.base = carpeta / "identidades"
        self.imprimir = imprimir
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        self._v, self._r, self._n, self._f = (
            ("\033[32m", "\033[31m", "\033[1m", "\033[0m") if color else ("",) * 4)
        self.fallos = 0
        self.total = 0

    # ---- salida ----------------------------------------------------------
    def titulo(self, texto):
        self.imprimir(f"\n{self._n}{texto}{self._f}")

    def comprobar(self, descripcion, condicion, detalle=""):
        self.total += 1
        if condicion:
            self.imprimir(f"  {self._v}✓{self._f} {descripcion}")
        else:
            self.fallos += 1
            self.imprimir(f"  {self._r}✗ {descripcion}{self._f} {detalle}")

    def debe_fallar(self, descripcion, excepcion, funcion, *args):
        try:
            funcion(*args)
        except excepcion as exc:
            self.comprobar(f"{descripcion} → rechazado: {exc}", True)
        except Exception as exc:  # rechazado, pero por un motivo inesperado
            self.comprobar(descripcion, False, f"(error inesperado {type(exc).__name__}: {exc})")
        else:
            self.comprobar(descripcion, False, "(¡fue ACEPTADO!)")

    # ---- flujo -----------------------------------------------------------
    def abrir(self, contenedor, usuario, gestor, firmante=None):
        """Mismo flujo que la pestaña Recibir de app.py."""
        if firmante is None:
            firmante = identificar_remitente(contenedor, self.base, gestor)["clave_publica_firma"]
        clave = self.claves[usuario]["clave_ecies"]
        return descifrar_contenedor_firmado(contenedor, clave, usuario, firmante, gestor)

    def ejecutar(self) -> bool:
        self.imprimir(f"{self._n}=== SECURE DIGITAL DOCUMENT VAULT · DEMO FINAL ==={self._f}")
        self.imprimir(f"Carpeta de trabajo: {self.carpeta}")

        self.titulo("[1] Identidades y historial persistente (D6)")
        gestor = abrir_gestor(self.base, HISTORIAL)
        for u in ("alice", "bob", "carol", "mallory"):
            info = crear_identidad(u, PASSWORD, self.base / u, gestor)
            self.imprimir(f"  · {u:<8} ECIES {info['huella_ecies'][:16]}…  firma {info['signer_id'][:16]}…")
        self.claves = {u: recuperar_identidad(PASSWORD, self.base / u)
                       for u in ("alice", "bob", "carol", "mallory")}
        self.comprobar("4 identidades: keystores cifrados + directorio público + registro D6",
                       all(gestor.existe_registro(u) for u in self.claves))

        self.titulo("[2] Alice cifra para Bob y Carol y firma (D2 + D3 + D5)")
        origen = self.carpeta / "contrato.txt"
        origen.write_bytes(MENSAJE)
        vault = self.carpeta / "contrato.vault"
        publicas = {u: cargar_identidad_publica(self.base / u, gestor)["clave_publica_ecies"]
                    for u in ("bob", "carol")}
        enviar_archivo_con_claves(origen, vault, publicas, self.claves["alice"]["clave_firma"], gestor)
        contenedor = leer_contenedor(vault)
        self.comprobar("contrato.vault creado con signer_id, signature_algorithm y signature",
                       {"signer_id", "signature", "signature_algorithm"} <= set(contenedor))
        self.comprobar("el remitente se identifica como alice por su signer_id (SHA-256 completo)",
                       identificar_remitente(contenedor, self.base, gestor)["usuario"] == "alice")

        self.titulo("[3] Recepción: firma → llave → revocación → descifrado")
        for u in ("bob", "carol"):
            self.comprobar(f"{u} verifica la firma y recupera el documento",
                           self.abrir(contenedor, u, gestor) == MENSAJE)

        self.titulo("[4] Ataques (todos deben bloquearse ANTES de descifrar)")
        alice_pub = cargar_identidad_publica(self.base / "alice")["clave_publica_firma"]
        for _clave, titulo, _texto, ataque in ataques.CATALOGO:
            self.debe_fallar(titulo, ErrorFirma, self.abrir, ataque(contenedor), "bob", gestor, alice_pub)
        self.debe_fallar("Mallory intenta abrirlo (no es destinataria)", DestinatarioNoAutorizado,
                         self.abrir, contenedor, "mallory", gestor)
        d3 = self.carpeta / "sin_firma_d3.vault"
        compartir_archivo(origen, d3, {"bob": publicas["bob"]})
        self.debe_fallar("Archivo .vault de D3 sin firma", ErrorFirma,
                         self.abrir, leer_contenedor(d3), "bob", gestor)

        self.titulo("[5] Revocación persistente de Bob (D6)")
        revocar_identidad("bob", self.base / "bob", gestor, "Compromiso de clave")
        gestor = abrir_gestor(self.base, HISTORIAL)  # simula reiniciar la aplicación
        resumen = resumen_identidad("bob", self.base, gestor)
        self.comprobar("tras reiniciar, el historial en disco dice: revocada",
                       resumen["estado"] == "revocada")
        self.comprobar("ecies.keystore y firma.keystore de bob ya no están en el repositorio",
                       not (self.base / "bob" / ARCHIVO_ECIES).exists()
                       and not (self.base / "bob" / ARCHIVO_FIRMA).exists())
        self.debe_fallar("Bob (aún con su clave en memoria) intenta abrir", ErrorCicloVida,
                         self.abrir, contenedor, "bob", gestor)
        self.debe_fallar("Alice intenta cifrar de nuevo para bob", ErrorCicloVida,
                         enviar_archivo_con_claves, origen, self.carpeta / "x.vault",
                         {"bob": publicas["bob"]}, self.claves["alice"]["clave_firma"], gestor)
        self.debe_fallar("Restaurar la clave revocada de bob (respaldo)", ErrorCicloVida,
                         gestor.registrar_clave_existente, "bob_respaldo",
                         self.claves["bob"]["clave_ecies"])
        self.comprobar("Carol, que no fue revocada, sigue abriendo el archivo",
                       self.abrir(contenedor, "carol", gestor) == MENSAJE)

        self.titulo("[6] Revocación del firmante (Alice)")
        revocar_identidad("alice", self.base / "alice", gestor, "Llave de firma comprometida")
        gestor = abrir_gestor(self.base, HISTORIAL)
        self.debe_fallar("Carol abre un archivo firmado por la llave revocada de alice",
                         FirmanteRevocado, self.abrir, contenedor, "carol", gestor)

        self.imprimir(f"\n{self._n}Resultado: {self.total - self.fallos}/{self.total} "
                      f"comprobaciones correctas{self._f}")
        return self.fallos == 0


def ejecutar(carpeta: Path, imprimir=print) -> bool:
    carpeta.mkdir(parents=True, exist_ok=True)
    if any(carpeta.iterdir()):
        raise SystemExit(f"La carpeta {carpeta} no está vacía; usa otra.")
    return Demo(carpeta, imprimir).ejecutar()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--carpeta", type=Path, help="carpeta (vacía) donde conservar los archivos")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):  # consolas de Windows sin UTF-8
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if args.carpeta:
        return 0 if ejecutar(args.carpeta) else 1
    with tempfile.TemporaryDirectory(prefix="vault_demo_") as temporal:
        return 0 if ejecutar(Path(temporal)) else 1


if __name__ == "__main__":
    sys.exit(main())

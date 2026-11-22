#!/usr/bin/env bash
# Secure Digital Document Vault - lanzador multiplataforma.
#
# Uso:  ./run.sh [app|preparar|test|demo|ayuda]
#   app       (por defecto) abre la aplicación gráfica (app.py)
#   preparar  crea las identidades de demostración (preparar_demo.py)
#   test      ejecuta la suite de pytest
#   demo      abre la demo D4 gráfica (demo_d4_gui.py)
#
# Variables opcionales:
#   PYTHON=/ruta/a/python3.12   fuerza el intérprete a usar
#
# Funciona en Linux (x86_64, arm64, armv7, ppc64le, s390x...), macOS (Intel y
# Apple Silicon) y Windows con Git Bash / WSL. Crea un entorno virtual propio
# de ESTA máquina en .venv y lo rehace si se copió desde otra arquitectura/SO.
set -euo pipefail

cd "$(dirname "$0")"

MIN_MAJOR=3
MIN_MINOR=12
VENV=".venv"
SELLO_PLATAFORMA="$VENV/.plataforma"
SELLO_REQS="$VENV/.requirements.sha256"

info()  { printf '[vault] %s\n' "$*"; }
error() { printf '[vault] ERROR: %s\n' "$*" >&2; }
fallar() { error "$*"; exit 1; }

SISTEMA="$(uname -s 2>/dev/null || echo desconocido)"
ARQUITECTURA="$(uname -m 2>/dev/null || echo desconocida)"
PLATAFORMA="$SISTEMA-$ARQUITECTURA"

case "$SISTEMA" in
  MINGW*|MSYS*|CYGWIN*) VENV_PY="$VENV/Scripts/python" ;;
  *)                    VENV_PY="$VENV/bin/python" ;;
esac

# ---- 1. Intérprete Python >= 3.12 -----------------------------------------
cumple_version() {
  "$1" -c "import sys; sys.exit(0 if sys.version_info >= ($MIN_MAJOR, $MIN_MINOR) else 1)" \
    >/dev/null 2>&1
}

buscar_python() {
  if [ -n "${PYTHON:-}" ]; then
    cumple_version "$PYTHON" || fallar "PYTHON=$PYTHON no es Python >= $MIN_MAJOR.$MIN_MINOR."
    printf '%s' "$PYTHON"
    return
  fi
  for candidato in python3.13 python3.12 python3 python py; do
    if command -v "$candidato" >/dev/null 2>&1 && cumple_version "$candidato"; then
      printf '%s' "$candidato"
      return
    fi
  done
  fallar "No se encontró Python >= $MIN_MAJOR.$MIN_MINOR. Instálalo (python.org, brew, apt, dnf...) o define PYTHON=/ruta/al/python."
}

# ---- 2. Entorno virtual propio de esta plataforma -------------------------
venv_valido() {
  [ -x "$VENV_PY" ] \
    && [ -f "$SELLO_PLATAFORMA" ] \
    && [ "$(cat "$SELLO_PLATAFORMA")" = "$PLATAFORMA" ] \
    && cumple_version "$VENV_PY"
}

preparar_venv() {
  if venv_valido; then
    return
  fi
  local base
  base="$(buscar_python)"
  if [ -e "$VENV" ]; then
    info "El entorno $VENV no es válido para $PLATAFORMA; se recreará."
    rm -rf "$VENV"
  fi
  info "Creando entorno virtual con $("$base" --version 2>&1) en $PLATAFORMA..."
  "$base" -m venv "$VENV" || fallar "No se pudo crear el entorno virtual (en Debian/Ubuntu: sudo apt install python3-venv)."
  printf '%s' "$PLATAFORMA" > "$SELLO_PLATAFORMA"
}

# ---- 3. Dependencias (solo si cambió requirements.txt) --------------------
hash_requirements() {
  "$VENV_PY" -c "import hashlib,sys; print(hashlib.sha256(open('requirements.txt','rb').read()).hexdigest())"
}

instalar_dependencias() {
  [ -f requirements.txt ] || fallar "Falta requirements.txt."
  local actual
  actual="$(hash_requirements)"
  if [ -f "$SELLO_REQS" ] && [ "$(cat "$SELLO_REQS")" = "$actual" ] \
     && "$VENV_PY" -c "import cryptography, pytest" >/dev/null 2>&1; then
    return
  fi
  info "Instalando dependencias..."
  if ! "$VENV_PY" -m pip install --quiet --disable-pip-version-check -r requirements.txt; then
    error "Falló la instalación de dependencias."
    error "En arquitecturas sin paquetes precompilados hacen falta herramientas de compilación:"
    error "  Debian/Ubuntu: sudo apt install build-essential libffi-dev libssl-dev python3-dev"
    error "  Fedora/RHEL:   sudo dnf install gcc libffi-devel openssl-devel python3-devel"
    error "  Alpine:        apk add build-base libffi-dev openssl-dev python3-dev cargo"
    error "  macOS:         xcode-select --install"
    exit 1
  fi
  printf '%s' "$actual" > "$SELLO_REQS"
}

# ---- 4. Requisitos de la interfaz gráfica ---------------------------------
verificar_gui() {
  if ! "$VENV_PY" -c "import tkinter" >/dev/null 2>&1; then
    error "Este Python no incluye Tkinter (necesario para la interfaz gráfica)."
    case "$SISTEMA" in
      Linux)  error "  Debian/Ubuntu: sudo apt install python3-tk   |  Fedora: sudo dnf install python3-tkinter"
              error "  Arch: sudo pacman -S tk                      |  Alpine: apk add py3-tkinter" ;;
      Darwin) error "  Homebrew: brew install python-tk@$MIN_MAJOR.$MIN_MINOR" ;;
      *)      error "  Reinstala Python marcando la opción 'tcl/tk and IDLE'." ;;
    esac
    exit 1
  fi
  if [ "$SISTEMA" = "Linux" ] && [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    error "No hay entorno gráfico (DISPLAY/WAYLAND_DISPLAY vacíos; ¿SSH o servidor?)."
    error "Usa './run.sh test' o ejecuta con un display virtual: xvfb-run ./run.sh app"
    exit 1
  fi
}

# ---- 5. Ejecución ---------------------------------------------------------
orden="${1:-app}"

case "$orden" in
  ayuda|-h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
  app|preparar|test|demo) ;;
  *) fallar "Orden desconocida: '$orden'. Usa: app | preparar | test | demo | ayuda" ;;
esac

preparar_venv
instalar_dependencias
info "Plataforma: $PLATAFORMA | $("$VENV_PY" --version 2>&1)"

case "$orden" in
  app)      verificar_gui; exec "$VENV_PY" app.py ;;
  demo)     verificar_gui; exec "$VENV_PY" demo_d4_gui.py ;;
  preparar) exec "$VENV_PY" preparar_demo.py ;;
  test)     exec "$VENV_PY" -m pytest -q ;;
esac

#!/usr/bin/env bash
# setup-dev.sh — install Python, Go, and Rust into tools/ for local, portable dev.
# Run once per machine. Re-run safely to update or repair broken installs.
# After this completes: source scripts/activate-dev.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TOOLS="$ROOT/tools"

# ── Pinned versions ──────────────────────────────────────────────────────────
GO_VERSION="1.22.5"
PYTHON_VERSION="3.12.13"
PYTHON_BUILD_DATE="20260610"   # python-build-standalone release tag
RUST_TOOLCHAIN="stable"

# ── Helpers ──────────────────────────────────────────────────────────────────
info()    { echo "[setup] $*"; }
success() { echo "[setup] ✓ $*"; }
warn()    { echo "[setup] ! $*" >&2; }
die()     { echo "[setup] ERROR: $*" >&2; exit 1; }

need_cmd() { command -v "$1" &>/dev/null || die "'$1' is required but not found. Install it and retry."; }

# Returns 0 if $1 >= $2 (both dotted version strings)
version_ge() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║         Axion Dev Environment Setup           ║"
echo "╚═══════════════════════════════════════════════╝"
echo "Project root : $ROOT"
echo "Tools dir    : $TOOLS"
echo ""

mkdir -p "$TOOLS"

# ── Detect OS / arch ─────────────────────────────────────────────────────────
OS_RAW="$(uname -s)"
ARCH_RAW="$(uname -m)"

case "$OS_RAW" in
    Darwin) OS="darwin" ;;
    Linux)  OS="linux"  ;;
    *)      die "Unsupported OS: $OS_RAW" ;;
esac

case "$ARCH_RAW" in
    x86_64)        ARCH="amd64" ; ARCH_TRIPLE_PYTHON="${OS/darwin/apple-darwin}"; ARCH_TRIPLE_PYTHON="x86_64-${ARCH_TRIPLE_PYTHON/linux/unknown-linux-gnu}" ;;
    arm64|aarch64) ARCH="arm64" ; ARCH_TRIPLE_PYTHON="${OS/darwin/apple-darwin}"; ARCH_TRIPLE_PYTHON="aarch64-${ARCH_TRIPLE_PYTHON/linux/unknown-linux-gnu}" ;;
    *)             die "Unsupported CPU arch: $ARCH_RAW" ;;
esac

info "Platform: ${OS}/${ARCH}"

# ── Python ────────────────────────────────────────────────────────────────────
echo ""
echo "─── Python ${PYTHON_VERSION} ─────────────────────────────────"

PY_MIN_REQUIRED="3.10"
PYTHON3=""
LOCAL_PYTHON="$TOOLS/python/bin/python3"

# 1. Prefer local install in tools/
if [ -x "$LOCAL_PYTHON" ]; then
    PYTHON3="$LOCAL_PYTHON"
    info "Found local Python: $("$PYTHON3" --version 2>&1)"
fi

# 2. Check system pythons — only accept >= 3.10
if [ -z "$PYTHON3" ]; then
    for candidate in python3.13 python3.12 python3.11 python3.10; do
        if command -v "$candidate" &>/dev/null; then
            candidate_ver="$("$candidate" -c 'import sys; print(".".join(map(str,sys.version_info[:2])))')"
            if version_ge "$candidate_ver" "$PY_MIN_REQUIRED" 2>/dev/null; then
                PYTHON3="$(command -v "$candidate")"
                info "Found system Python: $PYTHON3 ($("$PYTHON3" --version 2>&1))"
                break
            fi
        fi
    done
fi

# 3. Download python-build-standalone if still none found
if [ -z "$PYTHON3" ]; then
    need_cmd curl
    info "No Python ${PY_MIN_REQUIRED}+ found — downloading standalone Python ${PYTHON_VERSION}..."

    # Build the platform triple for python-build-standalone filenames
    case "${OS}-${ARCH}" in
        darwin-arm64)  PBS_TRIPLE="aarch64-apple-darwin" ;;
        darwin-amd64)  PBS_TRIPLE="x86_64-apple-darwin" ;;
        linux-arm64)   PBS_TRIPLE="aarch64-unknown-linux-gnu" ;;
        linux-amd64)   PBS_TRIPLE="x86_64-unknown-linux-gnu" ;;
        *)             die "No pre-built Python for ${OS}/${ARCH}" ;;
    esac

    PBS_FILE="cpython-${PYTHON_VERSION}+${PYTHON_BUILD_DATE}-${PBS_TRIPLE}-install_only_stripped.tar.gz"
    PBS_URL="https://github.com/indygreg/python-build-standalone/releases/download/${PYTHON_BUILD_DATE}/${PBS_FILE}"
    TMP="$(mktemp -d)"
    info "Downloading ${PBS_URL}..."
    curl -fsSL --progress-bar "$PBS_URL" -o "$TMP/$PBS_FILE"
    mkdir -p "$TOOLS/python"
    tar -C "$TOOLS/python" --strip-components=1 -xzf "$TMP/$PBS_FILE"
    rm -rf "$TMP"
    PYTHON3="$LOCAL_PYTHON"
    success "Python ${PYTHON_VERSION} installed at tools/python/"
fi

info "Using: $PYTHON3 ($("$PYTHON3" --version 2>&1))"

# ── Python venv ───────────────────────────────────────────────────────────────
VENV="$ROOT/venv"
# Recreate if broken (wrong Python version, dead symlinks, etc.)
if [ -d "$VENV" ]; then
    if ! "$VENV/bin/python3" --version &>/dev/null 2>&1; then
        warn "Existing venv is broken — recreating."
        rm -rf "$VENV"
    else
        existing_ver="$("$VENV/bin/python3" -c 'import sys; print(".".join(map(str,sys.version_info[:2])))')"
        if ! version_ge "$existing_ver" "$PY_MIN_REQUIRED" 2>/dev/null; then
            warn "Existing venv uses Python ${existing_ver} < ${PY_MIN_REQUIRED} — recreating."
            rm -rf "$VENV"
        fi
    fi
fi

if [ ! -d "$VENV" ]; then
    info "Creating virtual environment..."
    "$PYTHON3" -m venv "$VENV"
fi

info "Installing Python dependencies..."
"$VENV/bin/pip" install --upgrade pip -q
"$VENV/bin/pip" install -r "$ROOT/requirements.txt" -q
success "Python venv ready at venv/ ($(\"$VENV/bin/python3\" --version 2>&1))"

# ── Go ────────────────────────────────────────────────────────────────────────
echo ""
echo "─── Go ${GO_VERSION} ───────────────────────────────────────"

GO_DIR="$TOOLS/go"
GO_BIN="$GO_DIR/bin/go"
GOPATH="$TOOLS/gopath"

# Also accept a system Go that matches the required version
if [ ! -f "$GO_BIN" ]; then
    for candidate in "$HOME/.local/go/bin/go" /usr/local/go/bin/go /opt/homebrew/bin/go; do
        if [ -x "$candidate" ]; then
            cv="$("$candidate" version 2>/dev/null | awk '{print $3}' | sed 's/go//')"
            if version_ge "$cv" "$GO_VERSION" 2>/dev/null; then
                info "Using existing Go ${cv} at ${candidate}"
                mkdir -p "$GO_DIR/bin"
                ln -sf "$candidate" "$GO_BIN" 2>/dev/null || cp "$candidate" "$GO_BIN"
                break
            fi
        fi
    done
fi

install_go=true
if [ -f "$GO_BIN" ]; then
    installed_ver="$("$GO_BIN" version 2>/dev/null | awk '{print $3}' | sed 's/go//')"
    if version_ge "$installed_ver" "$GO_VERSION" 2>/dev/null; then
        success "Go ${installed_ver} already available."
        install_go=false
    else
        info "Found Go ${installed_ver}, installing ${GO_VERSION}..."
        rm -rf "$GO_DIR"
    fi
fi

if $install_go; then
    need_cmd curl
    TARBALL="go${GO_VERSION}.${OS}-${ARCH}.tar.gz"
    URL="https://go.dev/dl/${TARBALL}"
    TMP="$(mktemp -d)"
    info "Downloading ${URL}..."
    curl -fsSL --progress-bar "$URL" -o "$TMP/$TARBALL"
    mkdir -p "$GO_DIR"
    tar -C "$GO_DIR" --strip-components=1 -xzf "$TMP/$TARBALL"
    rm -rf "$TMP"
    success "Go ${GO_VERSION} installed at tools/go/"
fi

info "Downloading Go module dependencies..."
(cd "$ROOT/server-go" && GOPATH="$GOPATH" "$GO_BIN" mod download 2>&1 | tail -3 || true)
success "Go modules cached."

# ── Rust ─────────────────────────────────────────────────────────────────────
echo ""
echo "─── Rust (${RUST_TOOLCHAIN}) ─────────────────────────────────"

export CARGO_HOME="$TOOLS/cargo"
export RUSTUP_HOME="$TOOLS/rustup"
CARGO_BIN="$CARGO_HOME/bin/cargo"

if [ -f "$CARGO_BIN" ] && "$CARGO_BIN" --version &>/dev/null 2>&1; then
    success "Rust already installed: $("$CARGO_BIN" --version)"
else
    need_cmd curl
    info "Installing rustup + Rust ${RUST_TOOLCHAIN} into tools/..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | \
        RUSTUP_HOME="$RUSTUP_HOME" CARGO_HOME="$CARGO_HOME" \
        sh -s -- -y --no-modify-path --default-toolchain "$RUST_TOOLCHAIN"
    success "Rust installed at tools/cargo/ and tools/rustup/"
fi

info "Pre-fetching Rust crate dependencies..."
(cd "$ROOT/capture" && CARGO_HOME="$CARGO_HOME" "$CARGO_BIN" fetch --quiet 2>&1 || true)
success "Rust crates cached."

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔═══════════════════════════════════════════════╗"
echo "║               Setup complete!                 ║"
echo "╚═══════════════════════════════════════════════╝"
echo ""
echo "Activate the dev environment in your current shell:"
echo ""
echo "  source scripts/activate-dev.sh"
echo ""
echo "Or add to ~/.zshrc / ~/.bashrc for auto-activation when you cd here:"
echo ""
echo "  [[ -f $ROOT/scripts/activate-dev.sh ]] && source $ROOT/scripts/activate-dev.sh"
echo ""

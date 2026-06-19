#!/usr/bin/env bash
# activate-dev.sh — add local tools/ runtimes to PATH for the current shell.
# Usage: source scripts/activate-dev.sh   (do NOT execute directly)
#
# Safe to source multiple times; won't duplicate PATH entries.

# Resolve the project root from wherever this script lives.
# Works when sourced from bash and zsh.
if [ -n "${BASH_SOURCE:-}" ]; then
    _AXION_SCRIPT="${BASH_SOURCE[0]}"
elif [ -n "${ZSH_VERSION:-}" ]; then
    _AXION_SCRIPT="${(%):-%N}"
else
    _AXION_SCRIPT="$0"
fi
_AXION_ROOT="$(cd "$(dirname "$_AXION_SCRIPT")/.." && pwd)"
_AXION_TOOLS="$_AXION_ROOT/tools"

# ── Export tool-specific home dirs ───────────────────────────────────────────
export GOPATH="$_AXION_TOOLS/gopath"
export CARGO_HOME="$_AXION_TOOLS/cargo"
export RUSTUP_HOME="$_AXION_TOOLS/rustup"

# ── Build the new PATH segments (avoid duplicates) ───────────────────────────
_new_paths=(
    "$_AXION_ROOT/venv/bin"
    "$_AXION_TOOLS/go/bin"
    "$_AXION_TOOLS/cargo/bin"
    "$GOPATH/bin"
)

for _p in "${_new_paths[@]}"; do
    case ":$PATH:" in
        *":$_p:"*) ;; # already present
        *)          export PATH="$_p:$PATH" ;;
    esac
done

# ── SQLCipher dylib (macOS vendored build) ────────────────────────────────────
_VENDOR="$_AXION_ROOT/vendor/sqlcipher/lib"
if [ -d "$_VENDOR" ]; then
    case ":${DYLD_LIBRARY_PATH:-}:" in
        *":$_VENDOR:"*) ;;
        *) export DYLD_LIBRARY_PATH="$_VENDOR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" ;;
    esac
fi

# ── .env loader ──────────────────────────────────────────────────────────────
if [ -f "$_AXION_ROOT/.env" ]; then
    set -o allexport
    # shellcheck source=/dev/null
    source "$_AXION_ROOT/.env"
    set +o allexport
fi

# ── Report ───────────────────────────────────────────────────────────────────
echo "Axion dev env active  (root: $_AXION_ROOT)"
printf "  python  : %s\n" "$(python --version 2>&1 || echo 'not found')"
printf "  go      : %s\n" "$(go version 2>/dev/null || echo 'not found — run setup-dev.sh')"
printf "  cargo   : %s\n" "$(cargo --version 2>/dev/null || echo 'not found — run setup-dev.sh')"

unset _AXION_SCRIPT _AXION_ROOT _AXION_TOOLS _new_paths _p _VENDOR

#!/bin/bash
set -e
# Resolve project root regardless of where this script is called from
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ── Auto-activate local dev environment if available ─────────────────────────
if [ -f "scripts/activate-dev.sh" ]; then
    # Source silently so it doesn't spam output on every command
    source scripts/activate-dev.sh 2>/dev/null || true
fi

# ── Python helper: prefer venv, fall back to system python3 ──────────────────
PYTHON=""
if [ -x "venv/bin/python" ]; then
    PYTHON="venv/bin/python"
elif command -v python3 &>/dev/null; then
    PYTHON="python3"
else
    echo "Error: Python not found. Run: bash scripts/setup-dev.sh"; exit 1
fi

_ensure_venv() {
    if [ ! -d "venv" ]; then
        echo "venv not found — run 'bash scripts/setup-dev.sh' first"; exit 1
    fi
    if [ ! -x "venv/bin/python" ]; then
        echo "venv broken — run 'bash scripts/setup-dev.sh' to repair it"; exit 1
    fi
}

_load_env() {
    if [ -f .env ]; then
        set -o allexport
        # shellcheck source=/dev/null
        source .env
        set +o allexport
    fi
}

case "$1" in
  start)
    _ensure_venv
    _load_env

    if [ -z "${AXION_API_KEY:-}" ]; then
      echo "Error: AXION_API_KEY is not set."
      echo "Add it to .env:  AXION_API_KEY=your-secret-key"
      exit 1
    fi

    TLS_ARGS=""
    if [ -f "certs/server.crt" ] && [ -f "certs/server.key" ]; then
      TLS_ARGS="--ssl-certfile certs/server.crt --ssl-keyfile certs/server.key"
      SCHEME="https"
    else
      echo ""
      echo "WARNING: certs/ not found — running plain HTTP (dev only)."
      echo "         Generate dev certs: bash scripts/gen_dev_cert.sh"
      echo ""
      SCHEME="http"
    fi

    VENDOR="$ROOT/vendor/sqlcipher/lib"
    if [ -d "$VENDOR" ]; then
      export DYLD_LIBRARY_PATH="$VENDOR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    fi

    (sleep 3 && open "${SCHEME}://127.0.0.1:8000") &
    echo "Starting Axion Python server at ${SCHEME}://127.0.0.1:8000 ..."
    "$PYTHON" -m tacnet_sec.server.api --host 0.0.0.0 --port 8000 $TLS_ARGS
    ;;

  start-go)
    _load_env
    if [ -z "${AXION_API_KEY:-}" ]; then
      echo "Error: AXION_API_KEY is not set."; exit 1
    fi
    if [ -z "${DATABASE_URL:-}" ]; then
      echo "Error: DATABASE_URL is not set."; exit 1
    fi
    echo "Starting Axion Go server on :8000 ..."
    cd server-go && go run .
    ;;

  simulate)
    _ensure_venv
    _load_env
    VENDOR="$ROOT/vendor/sqlcipher/lib"
    if [ -d "$VENDOR" ]; then
      export DYLD_LIBRARY_PATH="$VENDOR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    fi
    DURATION="${2:-60}"
    echo "Running simulation for ${DURATION}s (server must already be running)..."
    "$PYTHON" -m tacnet_sec.cli --config configs/config.yaml --mode simulate --duration "$DURATION"
    ;;

  test)
    _ensure_venv
    echo "=== Python tests ==="
    "$PYTHON" -m pytest tacnet_sec/tests/ -v
    echo ""
    echo "=== Go middleware tests (no DB required) ==="
    (cd server-go && go test ./middleware/... -v)
    echo ""
    echo "=== Rust tests ==="
    (cd capture && cargo test -p axion-capture)
    ;;

  setup)
    exec bash scripts/setup-dev.sh
    ;;

  *)
    echo "Usage: bash scripts/axion.sh <command>"
    echo ""
    echo "Commands:"
    echo "  setup            Install Go, Rust, and Python venv into tools/ (run once per machine)"
    echo "  start            Start the Python server"
    echo "  start-go         Start the Go server (requires DATABASE_URL)"
    echo "  simulate [secs]  Send simulated attacks (default: 60s)"
    echo "  test             Run Python + Go middleware + Rust test suites"
    ;;
esac

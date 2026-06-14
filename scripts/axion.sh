#!/bin/bash
set -e
# Resolve project root regardless of where this script is called from
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

case "$1" in
  start)
    if [ ! -d "venv" ]; then
      echo "Creating virtual environment..."
      python3 -m venv venv
      source venv/bin/activate
      pip install --upgrade pip -q
      pip install -r requirements.txt -q
    else
      source venv/bin/activate
    fi

    if [ -f .env ]; then
      export $(grep -v '^#' .env | xargs)
    fi

    if [ -z "$AXION_API_KEY" ]; then
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

    # Expose the locally-built SQLCipher dylib to the Python runtime
    VENDOR="$ROOT/vendor/sqlcipher/lib"
    if [ -d "$VENDOR" ]; then
      export DYLD_LIBRARY_PATH="$VENDOR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    fi

    (sleep 3 && open "${SCHEME}://127.0.0.1:8000") &
    echo "Starting Axion Python server at ${SCHEME}://127.0.0.1:8000 ..."
    python -m tacnet_sec.server.api --host 0.0.0.0 --port 8000 $TLS_ARGS
    ;;

  start-go)
    if [ -z "$DATABASE_URL" ] && [ -f .env ]; then
      export $(grep -v '^#' .env | xargs)
    fi
    if [ -z "$AXION_API_KEY" ]; then
      echo "Error: AXION_API_KEY is not set."; exit 1
    fi
    echo "Starting Axion Go server on :8000 ..."
    cd server-go && go run .
    ;;

  simulate)
    if [ ! -d "venv" ]; then
      echo "venv not found — run 'bash scripts/axion.sh start' first"; exit 1
    fi
    source venv/bin/activate
    if [ -f .env ]; then export $(grep -v '^#' .env | xargs); fi
    VENDOR="$ROOT/vendor/sqlcipher/lib"
    if [ -d "$VENDOR" ]; then
      export DYLD_LIBRARY_PATH="$VENDOR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
    fi
    DURATION="${2:-60}"
    echo "Running simulation for ${DURATION}s (server must already be running)..."
    python -m tacnet_sec.cli --config configs/config.yaml --mode simulate --duration "$DURATION"
    ;;

  test)
    source venv/bin/activate 2>/dev/null || true
    echo "=== Python tests ==="
    python -m pytest tacnet_sec/tests/ -v
    echo ""
    echo "=== Rust tests ==="
    cd capture && cargo test -p axion-capture
    ;;

  *)
    echo "Usage: bash scripts/axion.sh <command>"
    echo "Commands:"
    echo "  start            Start the Python server"
    echo "  simulate [secs]  Send simulated attacks (default: 60s)"
    echo "  start-go         Start the Go server (requires DATABASE_URL)"
    echo "  test             Run Python + Rust test suites"
    ;;
esac

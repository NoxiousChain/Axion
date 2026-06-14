#!/usr/bin/env bash
# Generate a self-signed TLS certificate for local development.
# NOT for production — use a proper CA-signed cert or Let's Encrypt in prod.
set -euo pipefail

OUT_DIR="${1:-certs}"
mkdir -p "$OUT_DIR"

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$OUT_DIR/server.key" \
  -out    "$OUT_DIR/server.crt" \
  -subj   "/CN=axion-dev" \
  -addext "subjectAltName=IP:127.0.0.1,DNS:localhost"

chmod 600 "$OUT_DIR/server.key"
echo "Cert written to $OUT_DIR/server.crt"
echo "Key  written to $OUT_DIR/server.key"
echo ""
echo "Start server with TLS:"
echo "  AXION_API_KEY=<key> python -m tacnet_sec.server.api \\"
echo "    --ssl-certfile $OUT_DIR/server.crt --ssl-keyfile $OUT_DIR/server.key"

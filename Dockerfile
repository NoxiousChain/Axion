# ---- build stage ----
FROM python:3.11-alpine AS builder
WORKDIR /build

RUN apk add --no-cache gcc musl-dev linux-headers libffi-dev openssl-dev sqlcipher-dev

COPY requirements.txt .
# Exclude scapy (needs root + raw sockets; agent-only) from server image
RUN pip install --no-cache-dir --prefix=/install \
    $(grep -v "^scapy" requirements.txt | grep -v "^#" | grep -v "^$")

# ---- runtime stage ----
FROM python:3.11-alpine

RUN apk add --no-cache libffi openssl sqlcipher && \
    addgroup -S axion && \
    adduser -S axion -G axion

WORKDIR /app

COPY --from=builder /install /usr/local
COPY tacnet_sec/ ./tacnet_sec/
COPY configs/   ./configs/

# Data volume for SQLite file
RUN mkdir -p /data && chown axion:axion /data
VOLUME ["/data"]

# TLS certs volume (mount your certs here)
RUN mkdir -p /certs && chown axion:axion /certs

USER axion

ENV TACNET_SERVER_DB=/data/server_alerts.sqlite
# AXION_API_KEY must be injected at runtime — never bake secrets into the image
ENV AXION_API_KEY=""

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD wget -qO- --no-check-certificate https://localhost:8000/api/health 2>/dev/null \
        || wget -qO- http://localhost:8000/api/health || exit 1

# Override CMD to enable TLS:
#   docker run ... -e AXION_API_KEY=... \
#     axion-server --ssl-certfile /certs/server.crt --ssl-keyfile /certs/server.key
CMD ["python", "-m", "tacnet_sec.server.api"]

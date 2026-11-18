# Imagem única dos passos sem modelo (scan, fix, publish, notify). Versões pinadas (D-40).
# Bases fixadas por digest do índice multi-arquitetura (conferido no registry em 2026-11-17).
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS osv-scanner
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1

FROM maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237
RUN apt-get update \
    && apt-get install -y --no-install-recommends git python3 python3-venv \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
COPY --from=osv-scanner /out/osv-scanner /usr/local/bin/osv-scanner
COPY steps steps
COPY tests/contract tests/contract
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
USER 10001:10001

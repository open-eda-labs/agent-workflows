# Imagem única dos passos (scan, fix, publish, notify); só o fix chama o modelo, pelo gancho N2. Versões pinadas (D-40).
# Bases fixadas por digest do índice multi-arquitetura (conferido no registry em 2026-11-17).
FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS osv-scanner
RUN CGO_ENABLED=0 GOBIN=/out go install github.com/google/osv-scanner/v2/cmd/osv-scanner@v2.7.1

# Base: imagem do harness do N2 (agent-step-images: JDK 21, Maven 3.9.11, git, python3, Cline CLI e /opt/n2/n2-adapter, o N2_HOOK do fix).
# Trocar de harness é trocar só esta linha (G-P5). Ela já vem da maven:3.9.11-eclipse-temurin-21 fixada por digest.
# shortcut: tag sem digest, porque a imagem ainda não foi publicada; fixar por digest no primeiro push do agent-step-images
FROM ghcr.io/open-eda-labs/agent-step-images:0.1.0
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3-venv \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /opt/venv && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
COPY --from=osv-scanner /out/osv-scanner /usr/local/bin/osv-scanner
COPY steps steps
COPY tests/contract tests/contract
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 HOME=/tmp
USER 10001:10001

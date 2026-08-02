# Tensorfire — MCP model-testing server.
#
#     docker build -t tensorfire:latest .
#     docker run -p 8000:8000 tensorfire:latest
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    TENSORFIRE_HOST=0.0.0.0 \
    TENSORFIRE_PORT=8000 \
    TENSORFIRE_TRANSPORT=streamable-http

# build-essential/g++ for any packages that build from source; git and curl are
# used by some garak resources and by the health check.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential g++ git curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

# Drop root.
RUN useradd -m -u 10001 tensorfire && chown -R tensorfire:tensorfire /app
USER tensorfire

EXPOSE 8000

# Liveness: dedicated /health route (never hit /mcp — it requires the MCP
# handshake and 406s a bare GET).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS -o /dev/null "http://127.0.0.1:${TENSORFIRE_PORT}/health" || exit 1

CMD ["tensorfire"]

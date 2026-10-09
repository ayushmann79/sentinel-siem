# ── Build stage ────────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Runtime stage ──────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="SentinelSIEM"
LABEL org.opencontainers.image.description="Enterprise Security Information & Event Management"
LABEL org.opencontainers.image.authors="Ayushman Raj <ayushmann79@github.com>"
LABEL org.opencontainers.image.version="2.0.0"

# Create non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel sentinel

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application
COPY sentinelsiem/ ./sentinelsiem/
COPY frontend/     ./frontend/
COPY config/       ./config/
COPY .env.example  ./.env

# Data volume mount point
RUN mkdir -p /data && chown -R sentinel:sentinel /data /app

USER sentinel

ENV DUCKDB_PATH=/data/sentinel.duckdb \
    APP_HOST=0.0.0.0 \
    APP_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["python", "-m", "sentinelsiem.main"]

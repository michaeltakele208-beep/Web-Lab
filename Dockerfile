# ==============================================================================
# Vulnerability Assessment and Defense Lab (VADL) - Production Containerfile
# Multi-stage build enforcing non-root execution and minimal attack surface
# ==============================================================================

# Stage 1: Build & Dependency Wheel Assembly
FROM python:3.12-slim AS builder

WORKDIR /build

# Install build dependencies if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Stage 2: Hardened Runtime Environment
FROM python:3.12-slim AS runtime

# Security: Create non-root unprivileged service account
RUN groupadd -g 10001 vadlgroup && \
    useradd -u 10001 -g vadlgroup -s /sbin/nologin -M vadluser

# Security: Set Python runtime flags
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/home/vadluser/.local/bin:$PATH" \
    FLASK_CONFIG=production

WORKDIR /app

# Copy installed Python packages from builder to user home
COPY --from=builder /root/.local /home/vadluser/.local

# Create directory structure with correct unprivileged ownership
RUN mkdir -p /app/instance /app/reports && \
    chown -R vadluser:vadlgroup /app /home/vadluser

# Copy application source code with unprivileged ownership
COPY --chown=vadluser:vadlgroup app/ /app/app/
COPY --chown=vadluser:vadlgroup run.py /app/
COPY --chown=vadluser:vadlgroup pyproject.toml /app/

# Switch to non-root user
USER vadluser

# Expose internal application port
EXPOSE 5000

# Docker healthcheck using Python's standard library (no external curl/wget required)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health')" || exit 1

# Launch production WSGI application with Gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "run:app"]

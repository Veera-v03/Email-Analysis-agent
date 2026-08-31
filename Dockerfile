# ==============================================================================
# ScamON Enterprise Email Analysis Agent - Production Staging Dockerfile
# ==============================================================================

# Build stage
FROM python:3.13-slim AS builder

WORKDIR /app

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy build manifest and project metadata
COPY pyproject.toml README.md requirements.txt ./
COPY src/ ./src/

# Install build tools and project package with all production dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

# Runtime stage
FROM python:3.13-slim AS runner

WORKDIR /app

# Install runtime library dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root system user
RUN groupadd -g 10001 scamon && \
    useradd -u 10001 -g scamon -s /bin/false -m scamon

# Copy installed python packages and CLI executables from builder
COPY --from=builder /usr/local/lib/python3.13/site-packages /usr/local/lib/python3.13/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source code and configuration
COPY --chown=scamon:scamon . .

# Ensure data directories exist with proper permissions
RUN mkdir -p /app/data /app/data/memory && \
    chown -R scamon:scamon /app/data

# Switch to non-root user
USER scamon

# Expose standard FastAPI application port
EXPOSE 8000

# Container healthcheck using liveness endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production startup command using uvicorn ASGI server
ENTRYPOINT ["uvicorn", "src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]

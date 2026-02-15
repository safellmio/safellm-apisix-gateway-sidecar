FROM python:3.11-slim

# === SECURITY: Non-root user ===
# Create a non-root user for better container security
# Prevents privilege escalation in case of RCE (Remote Code Execution)
RUN groupadd --gid 1000 safellm && \
    useradd --uid 1000 --gid safellm --shell /bin/bash --create-home safellm

WORKDIR /app

# Install deps from pyproject first to maximize Docker cache reuse
COPY pyproject.toml /app/pyproject.toml
RUN python - <<'PY' > /tmp/requirements.txt
import tomllib
with open("pyproject.toml", "rb") as f:
    data = tomllib.load(f)
deps = list(data.get("project", {}).get("dependencies", []))
print("\n".join(deps))
PY
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Copy application code after deps to keep cache stable on code changes
COPY sidecar /app/sidecar

# Set ownership (audit logs go to Loki + stdout, not local files)
RUN chown -R safellm:safellm /app

# Add /app to PYTHONPATH so the sidecar package is visible
ENV PYTHONPATH=/app

# === SECURITY: Switch to non-root user ===
USER safellm

# === SERVER CONFIGURATION ===
# Max body size: 1MB (DoS protection)
# Workers: 1 (single-process, models in memory)
# Timeout: 30s (enough for ONNX inference)
#
# ⚠️ MULTI-WORKER NOTE:
# If you use granian with multiple workers, each worker
# loads its own model copy (~300-500MB per worker).
# The Redis cache circuit breaker is per-process (asyncio.Lock).
# For production, consider:
#   1. A model server pattern (separate model service)
#   2. Preload before fork (copy-on-write)
#
# Granian with body limit (production):
# CMD ["granian", "--interface", "asgi", "--port", "8000", "--workers", "1", 
#      "--http", "1", "--http1-buffer-size", "1048576", "app:app"]

# Uvicorn (development, simpler):
# Use -m to ensure relative imports work correctly.
CMD ["python", "-m", "sidecar.app"]

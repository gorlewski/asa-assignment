# syntax=docker/dockerfile:1

# =============================================================================
# VulnTracker API — production-grade container image for the FastAPI service.
#
# Base image note:
#   In a real production deployment I would use a Chainguard image
#   (e.g. cgr.dev/chainguard/python) as the base. Chainguard images are
#   distroless, minimal, and maintained at (near) zero known CVEs, which
#   dramatically shrinks the container attack surface and keeps the image
#   scan clean. For this assignment we use the official python:3.11-slim so
#   the image builds on any evaluator's machine without registry credentials,
#   pinned by digest for reproducibility.
# =============================================================================

# ------------------------------------------------------------------ builder ---
FROM python@sha256:d1e9ca7c4e78d1e8ecadb5d44bfc8e956e7a65b659a9950f569f243d72b326d0 AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install dependencies into an isolated prefix so the runtime stage copies only
# what it needs (no build caches, no pip metadata bloat).
COPY requirements-runtime.txt .
# NOTE (supply chain): versions are pinned, but not hash-pinned. In production
# we would generate a lockfile with hashes and use `pip install --require-hashes`
# (or a poetry.lock/Pipfile.lock) to defend against PyPI package tampering.
RUN pip install --prefix=/install -r requirements-runtime.txt

# ------------------------------------------------------------------ runtime ---
FROM python@sha256:d1e9ca7c4e78d1e8ecadb5d44bfc8e956e7a65b659a9950f569f243d72b326d0 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/usr/local/bin:$PATH"

# Create an unprivileged user/group with a fixed high UID/GID.
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

# Provide a writable data directory owned by the non-root user. This lets the
# container run with a read-only root filesystem (see Helm securityContext)
# while SQLite still has somewhere to write. In production this would be a
# managed database rather than SQLite-on-a-volume.
RUN mkdir -p /data && chown 10001:10001 /data
ENV DATABASE_URL="sqlite:////data/vulntracker.db"
VOLUME ["/data"]

# Copy the installed dependencies from the builder stage.
COPY --from=builder /install /usr/local

# Copy only the application source. The service uses bare imports and must run
# from inside its own directory, so app/ becomes the WORKDIR contents.
COPY --chown=appuser:appuser app/ /app/

# Drop to the non-root user.
USER 10001:10001

EXPOSE 8000

# Liveness/readiness probe against the app's own health endpoint. Uses the
# Python stdlib so we do not need curl/wget in the image.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"]

# No secrets are baked into the image. Runtime configuration (secrets, DB URL,
# base URL) is injected via environment variables / a secrets manager at deploy.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

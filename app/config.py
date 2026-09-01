import logging
import os
import secrets

logger = logging.getLogger(__name__)

# Database location is environment-driven so the container can point it at a
# writable volume while keeping the root filesystem read-only. Default is
# unchanged for local dev / CI.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vulntracker.db")

# Secrets are sourced from the environment (injected from a secrets manager in
# production via the Helm ExternalSecret). Nothing sensitive is hardcoded here.
#
# SECRET_KEY: if unset, we generate a random per-process key so local/dev and
# CI still work, but tokens will not survive a restart or work across replicas
# — production MUST set SECRET_KEY explicitly. We log a warning to make the
# ephemeral-key situation obvious.
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    SECRET_KEY = secrets.token_urlsafe(64)
    logger.warning(
        "SECRET_KEY is not set; generated an ephemeral key for this process. "
        "Set SECRET_KEY from your secrets manager in production."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database credentials — sourced from the environment, no defaults committed.
DB_USER = os.environ.get("DB_USER", "vulntracker_app")
DB_PASSWORD = os.environ.get("DB_PASSWORD")

# Internal service API key — sourced from the environment, no default committed.
ADMIN_API_KEY = os.environ.get("ADMIN_API_KEY")

NOTIFY_SERVICE_URL = "http://localhost:3001"

# Public base URL used as a fallback when building share links if the incoming
# request host is unavailable. Not a secret. Override via env in real deploys.
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8000")

# CORS allow-list. Comma-separated exact origins that may make credentialed
# cross-origin requests. Defaults to the local dev origin only; never reflect
# arbitrary origins.
CORS_ALLOWED_ORIGINS = [
    o.strip()
    for o in os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:8000").split(",")
    if o.strip()
]

# Share link lifetime (hours). The assignment requires 24h.
SHARE_LINK_TTL_HOURS = int(os.environ.get("SHARE_LINK_TTL_HOURS", "24"))

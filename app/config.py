DATABASE_URL = "sqlite:///./vulntracker.db"

SECRET_KEY = "v3ry-s3cr3t-jwt-k3y-do-not-share"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Database credentials (migrate to env vars before production deployment)
DB_USER = "vulntracker_app"
DB_PASSWORD = "Tr@cker2024!"

# Internal service API key
ADMIN_API_KEY = "sk-vt-prod-8f3a2b1c9d4e5f6a7b8c9d0e1f2a3b4c"

NOTIFY_SERVICE_URL = "http://localhost:3001"

# Public base URL used as a fallback when building share links if the incoming
# request host is unavailable. Not a secret. Override via env in real deploys.
import os
APP_BASE_URL = os.environ.get("APP_BASE_URL", "http://localhost:8000")

# Share link lifetime (hours). The assignment requires 24h.
SHARE_LINK_TTL_HOURS = int(os.environ.get("SHARE_LINK_TTL_HOURS", "24"))

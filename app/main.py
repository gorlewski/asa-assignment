import hashlib
import logging
import secrets
import traceback
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

import models
from auth import create_access_token, get_current_user, get_password_hash, verify_password
from config import APP_BASE_URL, NOTIFY_SERVICE_URL, SHARE_LINK_TTL_HOURS
from database import engine, get_db, search_scans_by_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="VulnTracker API",
    description="Vulnerability tracking and management REST API",
    version="1.0.0",
)


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "*"
    return response


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url, exc)
    return JSONResponse(
        status_code=500,
        content={
            "error": str(exc),
            "type": type(exc).__name__,
            "traceback": traceback.format_exc(),
            "path": str(request.url),
        },
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class UserRegister(BaseModel):
    username: str
    email: str
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"
    cve_id: Optional[str] = None
    affected_component: str
    remediation_notes: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[str] = None
    remediation_notes: Optional[str] = None


class ScanOut(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    remediation_notes: Optional[str]
    owner_id: int
    created_at: datetime

    class Config:
        from_attributes = True


class ShareCreate(BaseModel):
    # Optional password to protect the shared link. Never stored in plaintext.
    # Bound to <= 64 chars: bcrypt silently truncates input beyond 72 bytes
    # (so longer inputs would collide), and an unbounded value is a cheap DoS
    # vector against the KDF. 64 chars is comfortably within the bcrypt limit.
    password: Optional[str] = Field(default=None, min_length=1, max_length=64)


class ShareUrlOut(BaseModel):
    share_url: str
    expires_at: datetime


class SharedScanOut(BaseModel):
    """Public projection of a scan exposed via a share link.

    Deliberately omits owner_id and remediation_notes so a public link does not
    leak internal ownership or remediation detail beyond what is needed.
    """

    id: int
    title: str
    description: Optional[str]
    severity: str
    status: str
    cve_id: Optional[str]
    affected_component: str
    created_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _fire_notify(event: str, payload: dict) -> None:
    try:
        httpx.post(
            f"{NOTIFY_SERVICE_URL}/notify",
            json={"event": event, "payload": payload},
            timeout=5.0,
        )
    except Exception as exc:
        logger.warning("Notification service unreachable: %s", exc)


def _hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a share token.

    We store only this digest, so a database read does not reveal usable
    tokens. SHA-256 is appropriate here because the token itself is a
    256-bit CSPRNG value (secrets.token_urlsafe) and is not password-like,
    so it is not subject to brute force.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(payload: UserRegister, db: Session = Depends(get_db)):
    if db.query(models.User).filter(models.User.username == payload.username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(models.User).filter(models.User.email == payload.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = models.User(
        username=payload.username,
        email=payload.email,
        hashed_password=get_password_hash(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/auth/login")
def login(payload: UserLogin, db: Session = Depends(get_db)):
    # Never log credentials. Log the username only, for audit/troubleshooting.
    logger.info("Login attempt for username: %s", payload.username)
    user = db.query(models.User).filter(models.User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        logger.warning("Failed login for username: %s", payload.username)
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------------
# Scan routes
# ---------------------------------------------------------------------------

@app.get("/scans", response_model=List[ScanOut])
def list_scans(
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    return (
        db.query(models.ScanResult)
        .filter(models.ScanResult.owner_id == current_user.id)
        .offset(skip)
        .limit(limit)
        .all()
    )


@app.post("/scans", response_model=ScanOut, status_code=201)
def create_scan(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if payload.severity not in ("critical", "high", "medium", "low"):
        raise HTTPException(status_code=400, detail="severity must be critical | high | medium | low")
    scan = models.ScanResult(**payload.model_dump(), owner_id=current_user.id)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.created", {
        "id": scan.id,
        "title": scan.title,
        "severity": scan.severity,
        "owner": current_user.username,
    })
    return scan


@app.get("/scans/search")
def search_scans(
    q: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    if not q or len(q) < 2:
        raise HTTPException(status_code=400, detail="Search query must be at least 2 characters")
    results = search_scans_by_query(db, q)
    return {"results": results, "count": len(results)}


@app.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Enforce ownership: a user may only read their own scans. Without the
    # owner_id filter this was an IDOR allowing cross-tenant disclosure.
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.patch("/scans/{scan_id}", response_model=ScanOut)
def update_scan(
    scan_id: int,
    payload: ScanUpdate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if payload.status is not None:
        if payload.status not in ("open", "in_progress", "resolved"):
            raise HTTPException(status_code=400, detail="status must be open | in_progress | resolved")
        scan.status = payload.status
    if payload.remediation_notes is not None:
        scan.remediation_notes = payload.remediation_notes
    scan.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_fire_notify, "scan.updated", {
        "id": scan.id,
        "title": scan.title,
        "status": scan.status,
        "owner": current_user.username,
    })
    return scan


@app.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()


# ---------------------------------------------------------------------------
# Share routes
# ---------------------------------------------------------------------------

@app.post("/scans/{scan_id}/share", response_model=ShareUrlOut, status_code=201)
def create_share_link(
    scan_id: int,
    payload: ShareCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    # Ownership check: only the owner may share a scan. Return 404 (not 403) so
    # we do not confirm the existence of scans belonging to other users.
    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == scan_id,
        models.ScanResult.owner_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # 256-bit CSPRNG token; unguessable and non-sequential.
    token = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=SHARE_LINK_TTL_HOURS)

    # Pydantic already enforces 1..64 chars; reject whitespace-only here so an
    # effectively-empty password cannot be set.
    password_hash = None
    if payload.password is not None:
        if not payload.password.strip():
            raise HTTPException(status_code=400, detail="password must not be blank")
        password_hash = get_password_hash(payload.password)

    link = models.ShareLink(
        scan_id=scan.id,
        token_hash=_hash_token(token),
        password_hash=password_hash,
        expires_at=expires_at,
    )
    db.add(link)
    db.commit()

    # Build the URL from the incoming request host, falling back to the
    # configured base URL. Note: the Host header is client-controlled and can
    # be spoofed; acceptable for this prototype and documented in the README.
    base = str(request.base_url).rstrip("/") or APP_BASE_URL
    share_url = f"{base}/share/{token}"
    return ShareUrlOut(share_url=share_url, expires_at=expires_at)


@app.get("/share/{token}", response_model=SharedScanOut)
def get_shared_scan(
    token: str,
    password: Optional[str] = None,
    db: Session = Depends(get_db),
):
    # Bound the token length to avoid processing absurd input; a valid token is
    # a short URL-safe string. Any invalid length simply maps to the generic 404.
    if not token or len(token) > 128:
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    # Look up by token hash. A generic 404 is returned for unknown, expired or
    # otherwise invalid tokens to avoid leaking which case occurred.
    link = db.query(models.ShareLink).filter(
        models.ShareLink.token_hash == _hash_token(token)
    ).first()
    if not link:
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    if link.expires_at < datetime.utcnow():
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    if link.password_hash is not None:
        # Password required. Constant-time verification via passlib.
        if not password or not verify_password(password, link.password_hash):
            raise HTTPException(status_code=401, detail="Invalid or missing password")

    scan = db.query(models.ScanResult).filter(
        models.ScanResult.id == link.scan_id
    ).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Share link not found or expired")

    return scan


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "service": "vulntracker-api"}

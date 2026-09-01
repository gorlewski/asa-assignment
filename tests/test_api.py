import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))

from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    # TODO: add assertions for search results
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Shared Report Link (Task 1)
# ---------------------------------------------------------------------------

def _create_scan(token, title="Shareable finding"):
    return client.post("/scans", json={
        "title": title,
        "severity": "high",
        "affected_component": "GET /share",
    }, headers=auth_headers(token)).json()["id"]


def test_share_link_create_and_fetch():
    token = register_and_login()
    scan_id = _create_scan(token)

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    assert resp.status_code == 201
    body = resp.json()
    assert "share_url" in body and "/share/" in body["share_url"]

    share_token = body["share_url"].rsplit("/share/", 1)[1]
    pub = client.get(f"/share/{share_token}")
    assert pub.status_code == 200
    data = pub.json()
    assert data["id"] == scan_id
    # Public projection must not leak ownership.
    assert "owner_id" not in data
    assert "remediation_notes" not in data


def test_share_link_password_protected():
    token = register_and_login()
    scan_id = _create_scan(token)

    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "s3cret-share"},
        headers=auth_headers(token),
    )
    assert resp.status_code == 201
    share_token = resp.json()["share_url"].rsplit("/share/", 1)[1]

    # No password -> 401
    assert client.get(f"/share/{share_token}").status_code == 401
    # Wrong password -> 401
    assert client.get(f"/share/{share_token}?password=wrong").status_code == 401
    # Correct password -> 200
    ok = client.get(f"/share/{share_token}?password=s3cret-share")
    assert ok.status_code == 200
    assert ok.json()["id"] == scan_id


def test_share_link_invalid_token():
    assert client.get("/share/does-not-exist").status_code == 404


def test_share_link_expired():
    from datetime import datetime, timedelta
    token = register_and_login()
    scan_id = _create_scan(token)
    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(token))
    share_token = resp.json()["share_url"].rsplit("/share/", 1)[1]

    # Force expiry directly in the DB.
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
    import models  # noqa: E402
    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).first()
        link.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()

    assert client.get(f"/share/{share_token}").status_code == 404


def test_share_link_idor_other_users_scan():
    # Alice owns a scan; Bob must not be able to share it.
    alice = register_and_login(username="alice_idor", email="alice_idor@example.com")
    scan_id = _create_scan(alice)
    bob = register_and_login(username="bob_idor", email="bob_idor@example.com")

    resp = client.post(f"/scans/{scan_id}/share", json={}, headers=auth_headers(bob))
    assert resp.status_code == 404


def test_share_link_requires_auth():
    token = register_and_login()
    scan_id = _create_scan(token)
    # No Authorization header -> rejected.
    resp = client.post(f"/scans/{scan_id}/share", json={})
    assert resp.status_code in (401, 403)


def test_share_link_password_too_long_rejected():
    token = register_and_login()
    scan_id = _create_scan(token)
    # 65 chars exceeds the 64-char bound -> 422 validation error, preventing
    # silent bcrypt truncation collisions and KDF DoS.
    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "x" * 65},
        headers=auth_headers(token),
    )
    assert resp.status_code == 422


def test_share_link_password_blank_rejected():
    token = register_and_login()
    scan_id = _create_scan(token)
    resp = client.post(
        f"/scans/{scan_id}/share",
        json={"password": "   "},
        headers=auth_headers(token),
    )
    assert resp.status_code == 400

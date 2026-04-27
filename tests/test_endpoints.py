"""End-to-end tests for SecureShield, one per task.

Run with:    pytest -q
Run from the project root.
"""
import base64
import json
import os
import tempfile

import jwt as pyjwt
import pytest

# Each test gets an isolated temp DB + log file so order doesn't matter.
@pytest.fixture
def client(monkeypatch):
    tmp = tempfile.mkdtemp()
    monkeypatch.setenv("DB_PATH", os.path.join(tmp, "users.db"))
    monkeypatch.setenv("LOG_PATH", os.path.join(tmp, "security.log"))

    # Re-import config + app *after* env vars are set so paths are picked up.
    import importlib
    import config, models, auth, app as app_module

    importlib.reload(config)
    importlib.reload(models)
    importlib.reload(auth)
    importlib.reload(app_module)

    app_module._configure_security_log()
    models.init_db()
    app_module._seed_admin()

    yield app_module.app.test_client(), tmp


def _login(client, username, password):
    r = client.post("/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.get_json()
    return r.get_json()["access_token"]


# ---------- Task 1: bcrypt password hashing ----------
def test_passwords_are_hashed_not_plaintext(client):
    c, tmp = client
    c.post("/register", json={"username": "alice", "password": "Wonderland1!"})

    import sqlite3
    db = sqlite3.connect(os.path.join(tmp, "users.db"))
    row = db.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
    db.close()

    assert row is not None
    assert "Wonderland1!" not in row[0]            # plaintext never stored
    assert row[0].startswith("$2b$")                # bcrypt format


# ---------- Task 2: JWT issuance ----------
def test_login_returns_jwt_with_expected_claims(client):
    c, _ = client
    c.post("/register", json={"username": "alice", "password": "Wonderland1!"})
    token = _login(c, "alice", "Wonderland1!")

    # Decode without verifying just to inspect claims (we own the key, but
    # this also proves the payload is the standard 3-segment JWT).
    payload = pyjwt.decode(token, options={"verify_signature": False})
    assert payload["sub"] == "alice"
    assert payload["role"] == "user"
    assert "exp" in payload and "iat" in payload and "jti" in payload


# ---------- Task 3: token validation ----------
def test_protected_route_requires_valid_token(client):
    c, _ = client
    assert c.get("/profile").status_code == 401
    assert c.get("/profile",
                 headers={"Authorization": "Bearer not-a-jwt"}).status_code == 401


# ---------- Task 4: role-based routing ----------
def test_user_cannot_call_admin_route(client):
    c, _ = client
    c.post("/register", json={"username": "alice", "password": "Wonderland1!"})
    alice = _login(c, "alice", "Wonderland1!")
    r = c.delete("/user/1", headers={"Authorization": f"Bearer {alice}"})
    assert r.status_code == 403
    assert r.get_json()["error"] == "admin role required"


def test_admin_can_call_admin_route(client):
    c, _ = client
    c.post("/register", json={"username": "victim", "password": "x123!"})
    admin = _login(c, "admin", "Admin123!")
    r = c.delete("/user/2", headers={"Authorization": f"Bearer {admin}"})
    assert r.status_code == 200


# ---------- Task 5: token revocation (blacklist) ----------
def test_logout_blacklists_token(client):
    c, _ = client
    c.post("/register", json={"username": "alice", "password": "Wonderland1!"})
    alice = _login(c, "alice", "Wonderland1!")
    headers = {"Authorization": f"Bearer {alice}"}

    assert c.get("/profile", headers=headers).status_code == 200
    assert c.post("/logout", headers=headers).status_code == 200
    r = c.get("/profile", headers=headers)
    assert r.status_code == 401
    assert r.get_json()["error"] == "token revoked"


# ---------- Task 6: defensive logging ----------
def test_unauthorized_attempts_are_logged(client):
    c, tmp = client
    c.post("/register", json={"username": "alice", "password": "Wonderland1!"})
    alice = _login(c, "alice", "Wonderland1!")
    c.delete("/user/1", headers={"Authorization": f"Bearer {alice}"})  # 403
    c.get("/profile")                                                   # 401

    log = open(os.path.join(tmp, "security.log")).read()
    assert "403 | DELETE /user/1" in log
    assert "role 'user' attempted admin route" in log
    assert "401 | GET /profile" in log


# ---------- Tamper test (signature rejection) ----------
def test_tampered_role_is_rejected(client):
    c, _ = client
    c.post("/register", json={"username": "alice", "password": "Wonderland1!"})
    token = _login(c, "alice", "Wonderland1!")

    header_b64, payload_b64, _ = token.split(".")
    pad = lambda s: s + "=" * (-len(s) % 4)
    payload = json.loads(base64.urlsafe_b64decode(pad(payload_b64)))
    payload["role"] = "admin"

    forged = pyjwt.encode(payload, "wrong-secret", algorithm="HS256")
    r = c.delete("/user/1", headers={"Authorization": f"Bearer {forged}"})
    assert r.status_code == 401
    assert r.get_json()["error"] == "invalid token"

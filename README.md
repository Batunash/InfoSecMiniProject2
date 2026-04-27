# SecureShield — RBAC API

A Flask backend that demonstrates a complete authentication + role-based authorization
flow: bcrypt password hashing, JWT issuance, role gating, token revocation via blacklist,
and security logging of every unauthorized attempt.

> **Companion docs:** [`REPORT.md`](REPORT.md) — brief 2-page report covering
> (1) why salting defeats rainbow-table attacks and (2) the risks of putting
> sensitive data in a JWT payload.

## Features

| Task | Endpoint | Notes |
|------|----------|-------|
| 1. Hashing      | `POST /register` | Passwords stored as bcrypt hashes (per-password salt). |
| 2. JWT issuance | `POST /login`    | Returns HS256 JWT with `sub`, `role`, `exp`, `iat`, `jti`. |
| 3. Validation   | `@token_required` decorator | Verifies signature + expiry on every protected route. |
| 4. RBAC         | `GET /profile` (any) / `DELETE /user/<id>` (admin) | Enforced by `@admin_required`. |
| 5. Revocation   | `POST /logout`   | Adds the token's `jti` to an in-memory blacklist. |
| 6. Logging      | `security.log`   | Every 401/403 attempt: timestamp, status, route, reason, IP. |

## Setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

Optional — set a real signing key (otherwise a dev fallback is used):

```bash
# Windows (PowerShell)
$env:SECRET_KEY = "your-long-random-secret"
# macOS / Linux
export SECRET_KEY="your-long-random-secret"
```

## Run

```bash
python app.py
```

The server listens on `http://127.0.0.1:5000`. On first run it creates `users.db`,
opens `security.log`, and seeds an admin account:

- **username:** `admin`
- **password:** `Admin123!`

## Demo walkthrough (curl)

> Replace `<TOKEN>` with the `access_token` value from the matching login response.

### 1. Register a normal user

```bash
curl -X POST http://127.0.0.1:5000/register \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"alice\",\"password\":\"Wonderland1!\"}"
```

### 2. Login as the user

```bash
curl -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"alice\",\"password\":\"Wonderland1!\"}"
```

### 3. `GET /profile` (works for any logged-in user)

```bash
curl http://127.0.0.1:5000/profile \
  -H "Authorization: Bearer <ALICE_TOKEN>"
```

### 4. Access denied — user tries the admin route → **403**

```bash
curl -i -X DELETE http://127.0.0.1:5000/user/1 \
  -H "Authorization: Bearer <ALICE_TOKEN>"
# HTTP/1.1 403 FORBIDDEN
# {"error":"admin role required"}
```

### 5. Login as admin and delete a user

```bash
curl -X POST http://127.0.0.1:5000/login \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"admin\",\"password\":\"Admin123!\"}"

curl -X DELETE http://127.0.0.1:5000/user/2 \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```

### 6. Tamper test — edit role on jwt.io

1. Paste Alice's token at https://jwt.io.
2. Change `"role": "user"` to `"role": "admin"` in the payload.
3. Copy the new token (the signature is now invalid because jwt.io did not have your `SECRET_KEY`).
4. Send it:

```bash
curl -i -X DELETE http://127.0.0.1:5000/user/1 \
  -H "Authorization: Bearer <TAMPERED_TOKEN>"
# HTTP/1.1 401 UNAUTHORIZED
# {"error":"invalid token"}
```

### 7. Logout — token now blacklisted

```bash
curl -X POST http://127.0.0.1:5000/logout \
  -H "Authorization: Bearer <ALICE_TOKEN>"

# Reusing the same token afterwards:
curl -i http://127.0.0.1:5000/profile \
  -H "Authorization: Bearer <ALICE_TOKEN>"
# HTTP/1.1 401 UNAUTHORIZED
# {"error":"token revoked"}
```

## Project structure

```
.
├── app.py              # Flask app, route handlers, log setup
├── auth.py             # JWT helpers, blacklist, @token_required, @admin_required
├── models.py           # SQLite schema + user CRUD
├── config.py           # SECRET_KEY, JWT settings, DB/log paths, seed credentials
├── tests/
│   └── test_endpoints.py   # pytest suite, one test per task (8 tests)
├── REPORT.md           # 2-page brief report (salting + JWT payload risks)
├── requirements.txt
├── README.md
├── .gitignore
└── (runtime) users.db, security.log
```

## Running the tests

```bash
pip install pytest
pytest -q
```

## Security notes

- **Salting:** `flask_bcrypt` generates a unique salt per password, so identical
  passwords produce different hashes — defeating precomputed rainbow tables.
- **JWT payload:** the token only carries `sub` (username) and `role`; never store
  passwords or other secrets in the payload, since it is **not encrypted** — anyone
  with the token can base64-decode it.
- **Blacklist scope:** in-memory; a server restart clears it. Acceptable for this
  homework; production systems would persist revocations (e.g. Redis with TTL).
- **Dev secret:** `config.py` ships with a fallback `SECRET_KEY`. Override it in
  production via the `SECRET_KEY` environment variable.

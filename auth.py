import logging
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, jsonify, request

import config

security_logger = logging.getLogger("security")

BLACKLIST: set[str] = set()


def _log_unauthorized(status: int, reason: str):
    security_logger.info(
        "%d | %s %s | reason=%s | ip=%s",
        status,
        request.method,
        request.path,
        reason,
        request.remote_addr or "-",
    )


def generate_token(username: str, role: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=config.JWT_EXP_MINUTES),
        "jti": uuid.uuid4().hex,
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, config.SECRET_KEY, algorithms=[config.JWT_ALGORITHM])


def _extract_token() -> str | None:
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None
    return header.split(" ", 1)[1].strip() or None


def token_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        token = _extract_token()
        if not token:
            _log_unauthorized(401, "missing or malformed Authorization header")
            return jsonify(error="missing or malformed Authorization header"), 401

        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            _log_unauthorized(401, "expired token")
            return jsonify(error="token expired"), 401
        except jwt.InvalidTokenError as exc:
            _log_unauthorized(401, f"invalid token: {exc.__class__.__name__}")
            return jsonify(error="invalid token"), 401

        if payload.get("jti") in BLACKLIST:
            _log_unauthorized(401, "revoked token")
            return jsonify(error="token revoked"), 401

        g.current_user = {
            "username": payload["sub"],
            "role": payload["role"],
            "jti": payload["jti"],
        }
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @wraps(view)
    @token_required
    def wrapper(*args, **kwargs):
        if g.current_user["role"] != "admin":
            _log_unauthorized(
                403,
                f"role '{g.current_user['role']}' attempted admin route",
            )
            return jsonify(error="admin role required"), 403
        return view(*args, **kwargs)

    return wrapper


def revoke_current_token():
    BLACKLIST.add(g.current_user["jti"])

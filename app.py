import logging

from flask import Flask, g, jsonify, request
from flask_bcrypt import Bcrypt

import config
import models
from auth import (
    admin_required,
    generate_token,
    revoke_current_token,
    security_logger,
    token_required,
)

app = Flask(__name__)
bcrypt = Bcrypt(app)


def _configure_security_log():
    handler = logging.FileHandler(config.LOG_PATH)
    handler.setFormatter(
        logging.Formatter("%(asctime)s | %(message)s", datefmt="%Y-%m-%dT%H:%M:%S%z")
    )
    security_logger.addHandler(handler)
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False


def _seed_admin():
    if models.count_users() > 0:
        return
    pw_hash = bcrypt.generate_password_hash(config.SEED_ADMIN_PASSWORD).decode("utf-8")
    models.create_user(config.SEED_ADMIN_USERNAME, pw_hash, role="admin")
    app.logger.info("Seeded admin user '%s'", config.SEED_ADMIN_USERNAME)


@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify(error="username and password are required"), 400

    pw_hash = bcrypt.generate_password_hash(password).decode("utf-8")
    new_id = models.create_user(username, pw_hash, role="user")
    if new_id is None:
        return jsonify(error="username already taken"), 409

    return jsonify(id=new_id, username=username, role="user"), 201


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = models.get_user_by_username(username)
    if user is None or not bcrypt.check_password_hash(user["password_hash"], password):
        security_logger.info(
            "401 | %s %s | reason=failed login for username=%r | ip=%s",
            request.method,
            request.path,
            username,
            request.remote_addr or "-",
        )
        return jsonify(error="invalid credentials"), 401

    token = generate_token(user["username"], user["role"])
    return jsonify(access_token=token, token_type="Bearer"), 200


@app.get("/profile")
@token_required
def profile():
    return jsonify(username=g.current_user["username"], role=g.current_user["role"]), 200


@app.delete("/user/<int:user_id>")
@admin_required
def delete_user(user_id: int):
    deleted = models.delete_user(user_id)
    if deleted == 0:
        return jsonify(error="user not found"), 404
    return jsonify(deleted_id=user_id), 200


@app.post("/logout")
@token_required
def logout():
    revoke_current_token()
    return jsonify(message="token revoked"), 200


@app.get("/")
def index():
    return jsonify(
        service="SecureShield",
        endpoints=[
            "POST /register",
            "POST /login",
            "GET /profile",
            "DELETE /user/<id> (admin)",
            "POST /logout",
        ],
    )


def main():
    _configure_security_log()
    models.init_db()
    _seed_admin()
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()

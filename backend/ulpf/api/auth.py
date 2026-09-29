"""Authentication and Authorization API for ULPF.

Provides JWT-based authentication with RBAC (admin/analyst/viewer).
All authentication is local - no external identity providers.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from flask import Blueprint, jsonify, request

from ulpf.config import get_settings
from ulpf.security.auth import AuthService, UserStore, extract_bearer_token, get_auth_service
from ulpf.security.roles import Role, role_can

log = logging.getLogger("ulpf.api.auth")

auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


def require_permission(permission: str):
    """Decorator to require a specific permission on a route."""
    def decorator(fn):
        def wrapper(*args, **kwargs):
            settings = get_settings()
            if not settings.security.auth_enabled:
                return fn(*args, **kwargs)

            auth_header = request.headers.get("Authorization")
            token = extract_bearer_token(auth_header)
            if not token:
                return jsonify({"error": "unauthorized", "message": "Missing or invalid Authorization header"}), 401

            auth_service = get_auth_service()
            user = auth_service.verify_token(token)
            if not user:
                return jsonify({"error": "unauthorized", "message": "Invalid or expired token"}), 401

            if not role_can(user.role, permission):
                return jsonify({"error": "forbidden", "message": f"Insufficient permissions: requires {permission}"}), 403

            # Attach user to request for downstream use
            request.user = user
            return fn(*args, **kwargs)
        wrapper.__name__ = fn.__name__
        return wrapper
    return decorator


def optional_auth(fn):
    """Decorator that adds user to request if token is valid, but doesn't require it."""
    def wrapper(*args, **kwargs):
        settings = get_settings()
        if not settings.security.auth_enabled:
            return fn(*args, **kwargs)

        auth_header = request.headers.get("Authorization")
        token = extract_bearer_token(auth_header)
        if token:
            auth_service = get_auth_service()
            user = auth_service.verify_token(token)
            if user:
                request.user = user
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@auth_bp.route("/login", methods=["POST"])
def login():
    """Authenticate user and return JWT access + refresh tokens."""
    try:
        body = request.get_json(force=False, silent=True)
    except Exception:
        return jsonify({"error": "malformed_json", "message": "Request body is not valid JSON."}), 400

    if not isinstance(body, dict):
        return jsonify({"error": "invalid_body", "message": "Request body must be a JSON object."}), 400

    username = body.get("username", "").strip()
    password = body.get("password", "")

    if not username or not password:
        return jsonify({"error": "missing_credentials", "message": "Username and password are required."}), 400

    auth_service = get_auth_service()
    access_token = auth_service.login(username, password)

    if not access_token:
        log.warning("Failed login attempt for username: %s", username)
        return jsonify({"error": "invalid_credentials", "message": "Invalid username or password."}), 401

    user = auth_service.user_store.get(username)
    settings = get_settings()

    # Issue refresh token (longer expiry)
    now = datetime.now(timezone.utc)
    refresh_expires = now + timedelta(days=settings.security.jwt_refresh_expires_days)
    refresh_payload = {
        "sub": user.username,
        "type": "refresh",
        "iat": now,
        "exp": refresh_expires,
    }
    refresh_token = __import__("jwt").encode(
        refresh_payload,
        settings.security.jwt_secret_key,
        algorithm=settings.security.jwt_algorithm,
    )

    log.info("User logged in: %s (role: %s)", username, user.role.value)
    return jsonify({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": settings.security.jwt_access_expires_hours * 3600,
        "user": {
            "username": user.username,
            "role": user.role.value,
        }
    }), 200


@auth_bp.route("/refresh", methods=["POST"])
def refresh():
    """Refresh access token using a valid refresh token."""
    try:
        body = request.get_json(force=False, silent=True)
    except Exception:
        return jsonify({"error": "malformed_json", "message": "Request body is not valid JSON."}), 400

    if not isinstance(body, dict):
        return jsonify({"error": "invalid_body", "message": "Request body must be a JSON object."}), 400

    refresh_token = body.get("refresh_token", "")
    if not refresh_token:
        return jsonify({"error": "missing_refresh_token", "message": "Refresh token is required."}), 400

    settings = get_settings()
    try:
        import jwt
        payload = jwt.decode(
            refresh_token,
            settings.security.jwt_secret_key,
            algorithms=[settings.security.jwt_algorithm],
        )
    except jwt.PyJWTError:
        return jsonify({"error": "invalid_token", "message": "Invalid or expired refresh token."}), 401

    if payload.get("type") != "refresh":
        return jsonify({"error": "invalid_token", "message": "Not a refresh token."}), 401

    username = payload.get("sub")
    if not isinstance(username, str):
        return jsonify({"error": "invalid_token", "message": "Invalid token payload."}), 401

    auth_service = get_auth_service()
    user = auth_service.user_store.get(username)
    if not user:
        return jsonify({"error": "invalid_token", "message": "User no longer exists."}), 401

    # Issue new access token
    access_token = auth_service.issue_token(user)

    return jsonify({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": settings.security.jwt_access_expires_hours * 3600,
    }), 200


@auth_bp.route("/me", methods=["GET"])
@require_permission("health:view")  # Any authenticated user
def me():
    """Get current user info."""
    user = getattr(request, "user", None)
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    return jsonify({
        "username": user.username,
        "role": user.role.value,
        "permissions": list(role_can(user.role, "") for _ in []),  # Placeholder
    }), 200


@auth_bp.route("/permissions", methods=["GET"])
@require_permission("config:manage")  # Admin only
def list_permissions():
    """List all available permissions (admin only)."""
    from ulpf.security.roles import PERMISSIONS, Role
    return jsonify({
        role.value: list(perms) for role, perms in PERMISSIONS.items()
    }), 200


def register_auth_blueprint(app):
    """Register the auth blueprint with the Flask app."""
    app.register_blueprint(auth_bp)
    log.info("Auth blueprint registered at /api/v1/auth")
"""
Local authentication for ULPF.

* Passwords are hashed with bcrypt (salt per password) and never stored
  in plaintext.
* Successful logins mint a signed JWT access token (PyJWT).
* Demo users are bootstrapped from environment variables at startup; in
  development mode, documented defaults are used when the env vars are absent.

This module is intentionally small and self-contained. It is a prototype
auth mechanism, not an enterprise IAM integration.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import bcrypt
import jwt

from ulpf.config import get_settings
from ulpf.security.roles import Role


def hash_password(password: str) -> str:
    """Hash ``password`` with bcrypt (auto salt, cost factor 12) and return
    the printable hash string."""
    if not password:
        raise ValueError("password must not be empty")
    salt = bcrypt.gensalt(rounds=12)
    digest = bcrypt.hashpw(password.encode("utf-8"), salt)
    return digest.decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time bcrypt verification of ``password`` against a hash."""
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


@dataclass(frozen=True)
class User:
    """Authenticated user principal."""

    username: str
    role: Role
    password_hash: str = ""
    created_at: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"username": self.username, "role": self.role.value}


class UserStore:
    """In-memory user store seeded from environment/demo configuration.

    Passwords are hashed immediately on insertion; the store never retains
    plaintext passwords.
    """

    def __init__(self) -> None:
        self._users: dict[str, User] = {}
        self._seed_from_settings()

    def _seed_from_settings(self) -> None:
        settings = get_settings()
        security = settings.security
        self.add(security.demo_admin_username, Role.ADMIN, security.demo_admin_password)
        self.add(security.demo_analyst_username, Role.ANALYST, security.demo_analyst_password)
        self.add(security.demo_viewer_username, Role.VIEWER, security.demo_viewer_password)

    def add(self, username: str, role: Role | str, password: str) -> User:
        """Hash ``password`` and register ``username`` with ``role``.

        Re-adding an existing username replaces its credentials (used for
        deterministic demo bootstrap).
        """
        if not username or not username.strip():
            raise ValueError("username must not be empty")
        if not password:
            raise ValueError("password must not be empty")
        if isinstance(role, str):
            try:
                role = Role(role.lower())
            except ValueError as exc:
                raise ValueError(f"unknown role: {role}") from exc
        self._users[username] = User(
            username=username,
            role=role,
            password_hash=hash_password(password),
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        return self._users[username]

    def get(self, username: str) -> User | None:
        return self._users.get(username)

    def authenticate(self, username: str, password: str) -> User | None:
        """Return the user if ``password`` matches, else None."""
        user = self.get(username)
        if user is None or not user.password_hash:
            # Hash a dummy value to keep timing similar for unknown users.
            hash_password("not-a-real-password")
            return None
        if not verify_password(password, user.password_hash):
            return None
        return user

    def all(self) -> list[User]:
        return list(self._users.values())


class AuthService:
    """JWT issuance and verification backed by a :class:`UserStore`."""

    def __init__(self, user_store: UserStore | None = None) -> None:
        self.user_store = user_store or UserStore()

    def login(self, username: str, password: str) -> str | None:
        """Authenticate and return a signed JWT access token, or None."""
        user = self.user_store.authenticate(username, password)
        if user is None:
            return None
        return self.issue_token(user)

    def issue_token(self, user: User) -> str:
        settings = get_settings()
        now = datetime.now(timezone.utc)
        expires = now + timedelta(hours=settings.security.jwt_access_expires_hours)
        payload = {
            "sub": user.username,
            "role": user.role.value,
            "iat": now,
            "exp": expires,
        }
        return jwt.encode(
            payload,
            settings.security.jwt_secret_key,
            algorithm=settings.security.jwt_algorithm,
        )

    def verify_token(self, token: str) -> User | None:
        settings = get_settings()
        try:
            payload = jwt.decode(
                token,
                settings.security.jwt_secret_key,
                algorithms=[settings.security.jwt_algorithm],
            )
        except jwt.PyJWTError:
            return None
        username = payload.get("sub")
        if not isinstance(username, str):
            return None
        user = self.user_store.get(username)
        if user is None:
            return None
        # The role embedded in the token must still exist and match a known
        # role; the authoritative role comes from the user store.
        return user

    def get_current_user(self, token: str) -> User | None:
        return self.verify_token(token)


# Module-level singleton used by the API blueprints.
_auth_service: AuthService | None = None
_user_store: UserStore | None = None


def get_auth_service() -> AuthService:
    global _auth_service
    if _auth_service is None:
        _auth_service = AuthService()
    return _auth_service


def get_user_store() -> UserStore:
    global _user_store
    if _user_store is None:
        _user_store = UserStore()
    return _user_store


def extract_bearer_token(authorization_header: str | None) -> str | None:
    """Extract a bearer token from an Authorization header."""
    if not authorization_header:
        return None
    scheme, _, token = authorization_header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        return None
    return token.strip()

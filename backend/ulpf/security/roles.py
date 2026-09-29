"""
Role-Based Access Control (RBAC) for ULPF.

Lightweight prototype implementation:
  * Roles: ADMIN, ANALYST, VIEWER
  * Permissions are evaluated server-side on every protected API route.
  * Authentication is JWT-based; passwords are hashed with bcrypt at startup
    and are never stored in plaintext.

This is a self-contained local auth mechanism for the prototype. It is NOT an
enterprise IAM integration.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"

    @classmethod
    def values(cls) -> list[str]:
        return [role.value for role in cls]


# Permission model used by the route decorators. Each role is granted the
# minimum permissions required by the problem statement.
PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.ADMIN: frozenset(
        {
            "events:view",
            "events:search",
            "events:convert",
            "lineage:view",
            "schema:view",
            "schema:manage",
            "sources:view",
            "sources:manage",
            "config:manage",
            "analytics:view",
            "analytics:score",
            "parsers:view",
            "parsers:generate",
            "parsers:register",
            "ingest:create",
            "health:view",
            "metrics:view",
            "simulators:view",
            "simulators:manage",
        }
    ),
    Role.ANALYST: frozenset(
        {
            "events:view",
            "events:search",
            "events:convert",
            "lineage:view",
            "schema:view",
            "sources:view",
            "analytics:view",
            "analytics:score",
            "parsers:view",
            "parsers:generate",
            "ingest:create",
            "health:view",
            "metrics:view",
            "simulators:view",
            "simulators:manage",
        }
    ),
    Role.VIEWER: frozenset(
        {
            "events:view",
            "events:search",
            "sources:view",
            "schema:view",
            "analytics:view",
            "parsers:view",
            "health:view",
            "metrics:view",
            "simulators:view",
        }
    ),
}


def role_permissions(role: Role | str) -> frozenset[str]:
    """Return the permission set for a role (accepts enum or string)."""
    if isinstance(role, str):
        try:
            role = Role(role.lower())
        except ValueError:
            return frozenset()
    return PERMISSIONS.get(role, frozenset())


def role_can(role: Role | str, permission: str) -> bool:
    """Return True if ``role`` is granted ``permission``."""
    return permission in role_permissions(role)

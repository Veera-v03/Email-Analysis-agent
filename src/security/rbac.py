"""Role-Based Access Control permissions registry and multi-tenant isolation validation."""

from __future__ import annotations

# Predefined granular security permissions
PERMISSIONS = {
    "org:read",
    "org:write",
    "user:read",
    "user:write",
    "investigation:create",
    "investigation:read",
    "investigation:delete",
    "config:read",
    "config:write",
    "audit_log:read",
    "memory:search",
    "memory:write",
}

# Base permission map for individual roles
ROLE_DIRECT_PERMISSIONS = {
    "super_admin": PERMISSIONS,  # Super Admin has all permissions
    "security_admin": {
        "user:read",
        "user:write",
        "config:read",
        "config:write",
        "audit_log:read",
        "investigation:read",
    },
    "soc_analyst": {
        "investigation:create",
        "investigation:read",
        "audit_log:read",
        "memory:search",
        "memory:write",
    },
    "analyst": {
        "investigation:create",
        "investigation:read",
        "memory:search",
    },
    "read_only": {
        "investigation:read",
    },
    "api_client": {
        "investigation:create",
        "investigation:read",
    },
}

# Role hierarchy tree (Parent roles inherit child roles' permissions)
ROLE_HIERARCHY = {
    "super_admin": ["security_admin", "soc_analyst"],
    "security_admin": ["analyst"],
    "soc_analyst": ["analyst"],
    "analyst": ["read_only"],
    "read_only": [],
    "api_client": ["read_only"],
}


def get_role_permissions(role: str) -> set[str]:
    """Compile a set of direct and inherited permissions for a given role."""
    resolved_permissions = set(ROLE_DIRECT_PERMISSIONS.get(role, []))

    # Traverse hierarchy recursively
    children = ROLE_HIERARCHY.get(role, [])
    for child in children:
        resolved_permissions.update(get_role_permissions(child))

    return resolved_permissions


def verify_rbac_permission(user_roles: list[str], required_permission: str) -> bool:
    """Check if any user role possesses the required permission."""
    for role in user_roles:
        if required_permission in get_role_permissions(role):
            return True
    return False


def verify_tenant_isolation(
    user_org_id: str,
    resource_org_id: str | None,
    user_roles: list[str],
) -> bool:
    """Enforce strict multi-tenant boundary checks.

    Super Admin role can bypass tenant bounds.
    """
    if "super_admin" in user_roles:
        return True
    if resource_org_id is None:
        return False
    return user_org_id == resource_org_id

"""Role-Based Access Control (RBAC) and tenant isolation evaluation service."""

from __future__ import annotations

from uuid import UUID

from src.config.logging import get_logger
from src.events.base_event import BaseEvent
from src.events.iam_events import PermissionDeniedEvent
from src.interfaces.event_publisher import IEventPublisher
from src.security.exceptions import AuthorizationError
from src.security.models import AuthenticatedUser, Permission, Role

logger = get_logger("scamon.security.rbac")


class AuthorizationService:
    """Evaluates security rules, role hierarchies, and tenant boundary isolation."""

    def __init__(self, event_publisher: IEventPublisher | None = None) -> None:
        self.event_publisher = event_publisher

    async def authorize_permission(
        self,
        user: AuthenticatedUser,
        required_permission: Permission | str,
        resource: str = "system",
    ) -> None:
        """Verify that user possesses the required permission.

        Raises:
            AuthorizationError: If user lacks required permission.
        """
        perm_str = (
            required_permission.value
            if isinstance(required_permission, Permission)
            else required_permission
        )

        if perm_str not in user.permissions:
            logger.warning(
                "Permission denied for user '%s' (tenant '%s'): missing permission '%s'",
                user.user_id,
                user.tenant_id,
                perm_str,
            )
            await self._publish_event(
                PermissionDeniedEvent(
                    tenant_id=user.tenant_id,
                    user_id=user.user_id,
                    required_permission=perm_str,
                    resource=resource,
                )
            )
            raise AuthorizationError(
                message=f"Access denied: missing required permission '{perm_str}'",
                details={
                    "user_id": str(user.user_id),
                    "required_permission": perm_str,
                    "resource": resource,
                },
            )

    def authorize_role(
        self, user: AuthenticatedUser, allowed_roles: list[Role | str]
    ) -> None:
        """Verify that user possesses one of the allowed RBAC roles."""
        role_strings = [r.value if isinstance(r, Role) else r for r in allowed_roles]
        if user.role.value not in role_strings:
            raise AuthorizationError(
                message=f"Access denied: required role in {role_strings}",
                details={"user_role": user.role.value, "allowed_roles": role_strings},
            )

    def verify_tenant_isolation(
        self, user: AuthenticatedUser, resource_tenant_id: UUID
    ) -> None:
        """Enforce strict multi-tenant boundary isolation.

        Raises:
            AuthorizationError: If user tenant_id does not match resource_tenant_id.
        """
        if user.role == Role.SUPER_ADMIN:
            # Super Admin bypasses single-tenant constraint
            return

        if user.tenant_id != resource_tenant_id:
            logger.error(
                "Tenant isolation violation: user tenant '%s' attempted cross-tenant access to '%s'",
                user.tenant_id,
                resource_tenant_id,
            )
            raise AuthorizationError(
                message="Cross-tenant access violation: resource belongs to another organization",
                details={
                    "user_tenant_id": str(user.tenant_id),
                    "resource_tenant_id": str(resource_tenant_id),
                },
            )

    async def _publish_event(self, event: BaseEvent) -> None:
        if self.event_publisher:
            try:
                await self.event_publisher.publish(event)
            except Exception as exc:
                logger.error("Failed to publish RBAC audit event: %s", exc)


def verify_rbac_permission(
    user_roles: list[str], required_permission: str = "analyst"
) -> bool:
    """Legacy helper for RBAC permission checking."""
    if not user_roles:
        return False
    roles_lower = [r.lower() for r in user_roles]
    if "admin" in roles_lower or "super_admin" in roles_lower:
        return True

    perm_lower = required_permission.lower()
    if "analyst" in roles_lower or "soc_analyst" in roles_lower:
        if perm_lower in (
            "analyst",
            "investigation:read",
            "investigation:create",
            "read",
            "create",
            "memory:search",
            "memory:read",
        ):
            return True
    return False


def verify_tenant_isolation(
    user_org_id: str, resource_org_id: str, user_roles: list[str] | None = None
) -> bool:
    """Legacy helper for tenant boundary validation."""
    if user_roles and "super_admin" in [r.lower() for r in user_roles]:
        return True
    return user_org_id == resource_org_id

"""JWT token creation, validation, rotation, and revocation tracking."""

from __future__ import annotations

import threading
import time
from uuid import UUID, uuid4

import jwt

from src.config.logging import get_logger
from src.security.exceptions import InvalidTokenError, TokenExpiredError
from src.security.keys import RSAKeyManager
from src.security.models import (
    ROLE_PERMISSIONS_MAP,
    Permission,
    Role,
    TokenPairDTO,
    TokenPayloadDTO,
)

logger = get_logger("scamon.security.token_manager")


class TokenRevocationManager:
    """Thread-safe revocation store for invalidated JWT JTI identifiers."""

    def __init__(self) -> None:
        self._revoked_jtis: set[UUID] = set()
        self._lock = threading.RLock()

    def revoke(self, jti: UUID) -> None:
        """Mark a JWT JTI as revoked."""
        with self._lock:
            self._revoked_jtis.add(jti)
            logger.info("Revoked JWT token JTI: %s", jti)

    def is_revoked(self, jti: UUID) -> bool:
        """Check if a JWT JTI has been revoked."""
        with self._lock:
            return jti in self._revoked_jtis


class TokenManager:
    """Enterprise RS256 JWT Token issuer, decoder, and validator."""

    def __init__(
        self,
        key_manager: RSAKeyManager | None = None,
        access_token_expire_minutes: int = 30,
        refresh_token_expire_days: int = 7,
    ) -> None:
        self.key_manager = key_manager or RSAKeyManager()
        self.access_token_expire_seconds = access_token_expire_minutes * 60
        self.refresh_token_expire_seconds = refresh_token_expire_days * 24 * 3600
        self.revocation_manager = TokenRevocationManager()
        self.issuer = "scamon.enterprise"

    def create_access_token(
        self,
        user_id: UUID,
        tenant_id: UUID,
        email: str,
        role: Role | str,
        permissions: list[str] | None = None,
    ) -> tuple[str, UUID, int]:
        """Generate an RS256 signed JWT access token.

        Returns:
            Tuple of (signed_jwt_string, jti_uuid, expires_in_seconds).
        """
        role_enum = Role(role) if isinstance(role, str) else role
        if permissions is None:
            granted = ROLE_PERMISSIONS_MAP.get(role_enum, set())
            permissions = [p.value for p in granted]

        now = int(time.time())
        exp = now + self.access_token_expire_seconds
        jti = uuid4()

        payload = {
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "email": email,
            "role": role_enum.value,
            "permissions": permissions,
            "token_type": "access",
            "jti": str(jti),
            "iat": now,
            "nbf": now,
            "exp": exp,
            "iss": self.issuer,
        }

        token = jwt.encode(
            payload,
            self.key_manager.private_key_pem,
            algorithm="RS256",
        )
        return token, jti, self.access_token_expire_seconds

    def create_refresh_token(
        self,
        user_id: UUID,
        tenant_id: UUID,
        email: str,
        role: Role | str,
    ) -> tuple[str, UUID, int]:
        """Generate an RS256 signed JWT refresh token."""
        role_enum = Role(role) if isinstance(role, str) else role
        now = int(time.time())
        exp = now + self.refresh_token_expire_seconds
        jti = uuid4()

        payload = {
            "sub": str(user_id),
            "tenant_id": str(tenant_id),
            "email": email,
            "role": role_enum.value,
            "token_type": "refresh",
            "jti": str(jti),
            "iat": now,
            "nbf": now,
            "exp": exp,
            "iss": self.issuer,
        }

        token = jwt.encode(
            payload,
            self.key_manager.private_key_pem,
            algorithm="RS256",
        )
        return token, jti, self.refresh_token_expire_seconds

    def create_token_pair(
        self,
        user_id: UUID,
        tenant_id: UUID,
        email: str,
        role: Role | str,
        permissions: list[str] | None = None,
    ) -> TokenPairDTO:
        """Issue an access token and refresh token pair."""
        access_tok, _, expires_in = self.create_access_token(
            user_id, tenant_id, email, role, permissions
        )
        refresh_tok, _, _ = self.create_refresh_token(user_id, tenant_id, email, role)
        return TokenPairDTO(
            access_token=access_tok,
            refresh_token=refresh_tok,
            expires_in=expires_in,
        )

    def decode_token(
        self, token: str, expected_type: str = "access"
    ) -> TokenPayloadDTO:
        """Validate signature, expiry, and revocation for a JWT token."""
        try:
            raw_payload = jwt.decode(
                token,
                self.key_manager.public_key_pem,
                algorithms=["RS256"],
                issuer=self.issuer,
            )
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpiredError("JWT token signature has expired") from exc
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(f"Invalid JWT token: {exc}") from exc

        token_type = raw_payload.get("token_type")
        if token_type != expected_type:
            raise InvalidTokenError(
                f"Invalid token type '{token_type}', expected '{expected_type}'"
            )

        jti = UUID(raw_payload["jti"])
        if self.revocation_manager.is_revoked(jti):
            raise InvalidTokenError("JWT token has been revoked")

        role_enum = Role(raw_payload["role"])
        permissions = raw_payload.get("permissions", [])
        if not permissions and expected_type == "access":
            granted = ROLE_PERMISSIONS_MAP.get(role_enum, set())
            permissions = [p.value for p in granted]

        return TokenPayloadDTO(
            sub=UUID(raw_payload["sub"]),
            tenant_id=UUID(raw_payload["tenant_id"]),
            email=raw_payload["email"],
            role=role_enum,
            permissions=permissions,
            token_type=token_type,
            jti=jti,
            exp=raw_payload["exp"],
            iat=raw_payload["iat"],
        )

    def revoke_token(self, jti: UUID) -> None:
        """Revoke a token by its JTI identifier."""
        self.revocation_manager.revoke(jti)

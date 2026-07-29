"""Cryptographic security utilities for Password Hashing, JWT Tokens, and API Key validation."""

from __future__ import annotations

import base64
import hashlib
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from src.config.enterprise_config import settings
from src.utils.logging import get_logger

logger = get_logger(__name__)

# Simple in-memory token revocation registry
REVOKED_TOKENS: set[str] = set()


def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
    salt_b64 = base64.b64encode(salt).decode("utf-8")
    key_b64 = base64.b64encode(key).decode("utf-8")
    return f"pbkdf2_sha256$100000${salt_b64}${key_b64}"


def verify_password(password: str, hashed_password: str) -> bool:
    """Verify password match against pbkdf2_sha256 formatted hash."""
    try:
        parts = hashed_password.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = base64.b64decode(parts[2])
        key_expected = base64.b64decode(parts[3])
        key_actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, iterations
        )
        return key_expected == key_actual
    except Exception as e:
        logger.error("Password verification error: %s", e)
        return False


def generate_api_key() -> tuple[str, str]:
    """Generate a clean raw API key and its SHA-256 verification hash.

    Returns:
        (raw_api_key, key_hash)
    """
    raw_key = f"sh_key_{base64.b64encode(os.urandom(24)).decode('utf-8').replace('+', '').replace('/', '')}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return raw_key, key_hash


def verify_api_key(raw_key: str, key_hash: str) -> bool:
    """Check API Key match using hash comparison."""
    actual_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    return actual_hash == key_hash


def create_jwt_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """Generate JWT Token with claim payload."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(UTC) + expires_delta
    else:
        expire = datetime.now(UTC) + timedelta(
            minutes=settings.access_token_expire_minutes
        )

    to_encode.update(
        {
            "exp": int(expire.timestamp()),
            "iat": int(datetime.now(UTC).timestamp()),
            "nbf": int(datetime.now(UTC).timestamp()),
        }
    )
    secret_key = (
        settings.get_secret("SECRET_KEY")
        or "super-secret-key-change-in-production-123456789"
    )
    return jwt.encode(to_encode, secret_key, algorithm=settings.jwt_algorithm)


def decode_jwt_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token, verifying signature and expiration.

    Raises:
        jwt.PyJWTError: If token is expired, invalid, or revoked.
    """
    if token in REVOKED_TOKENS:
        raise jwt.InvalidTokenError("Token has been revoked.")

    secret_key = (
        settings.get_secret("SECRET_KEY")
        or "super-secret-key-change-in-production-123456789"
    )
    return jwt.decode(token, secret_key, algorithms=[settings.jwt_algorithm])


def revoke_token(token: str) -> None:
    """Add JWT token to the blacklisted token revocation list."""
    REVOKED_TOKENS.add(token)

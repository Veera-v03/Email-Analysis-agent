"""Cryptography Provider abstraction for DKIM RSA signature verification."""

from __future__ import annotations

import base64
from typing import Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_der_public_key,
    load_pem_public_key,
)

from src.config.logging import get_logger

logger = get_logger("scamon.authentication.crypto")


@runtime_checkable
class ICryptoProvider(Protocol):
    """Protocol interface for cryptographic signature verification."""

    def verify_rsa_signature(
        self, public_key_b64_or_pem: str, data: bytes, signature: bytes
    ) -> bool:
        """Verify RSA-SHA256 signature against public key."""
        ...


class RSACryptoProvider(ICryptoProvider):
    """Production-grade Cryptography Provider using cryptography primitives."""

    def verify_rsa_signature(
        self, public_key_b64_or_pem: str, data: bytes, signature: bytes
    ) -> bool:
        if not public_key_b64_or_pem or not signature:
            return False

        try:
            # 1. Parse Public Key
            clean_key = public_key_b64_or_pem.strip()
            if "BEGIN PUBLIC KEY" in clean_key:
                pub_key = load_pem_public_key(clean_key.encode("utf-8"))
            else:
                der_bytes = base64.b64decode(clean_key)
                pub_key = load_der_public_key(der_bytes)

            if not isinstance(pub_key, rsa.RSAPublicKey):
                return False

            # 2. Verify RSA-SHA256 Signature
            pub_key.verify(
                signature=signature,
                data=data,
                padding=padding.PKCS1v15(),
                algorithm=hashes.SHA256(),
            )
            return True
        except Exception as exc:
            logger.debug("RSA signature verification failed: %s", exc)
            return False

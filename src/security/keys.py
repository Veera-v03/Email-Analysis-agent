"""RSA 2048-bit Key Pair management for RS256 JWT signing."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.config.logging import get_logger

logger = get_logger("scamon.security.keys")


class RSAKeyManager:
    """Manages RSA key pairs for enterprise RS256 JWT token signing and verification."""

    def __init__(
        self,
        private_key_pem: str | None = None,
        public_key_pem: str | None = None,
    ) -> None:
        if private_key_pem and public_key_pem:
            self._private_key_pem = private_key_pem
            self._public_key_pem = public_key_pem
        else:
            # Generate in-memory RSA 2048-bit key pair
            logger.info(
                "Generating ephemeral 2048-bit RSA key pair for RS256 token signing."
            )
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            self._private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")

            self._public_key_pem = (
                private_key.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode("utf-8")
            )

    @property
    def private_key_pem(self) -> str:
        """Return RSA private key in PEM format."""
        return self._private_key_pem

    @property
    def public_key_pem(self) -> str:
        """Return RSA public key in PEM format."""
        return self._public_key_pem

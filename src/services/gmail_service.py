"""Gmail API integration handling OAuth 2.0 flow and fetching recent emails."""

from __future__ import annotations

import base64
import json
import os
import urllib.parse
from pathlib import Path
from typing import Any, cast

import requests

from src.utils.logging import get_logger

logger = get_logger(__name__)

DEFAULT_CREDENTIALS_FILE = Path("credentials.json")
DEFAULT_TOKEN_FILE = Path("token.json")

GMAIL_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"


def resolve_credentials_path(custom_path: Path | str | None = None) -> Path:
    """Resolve credentials file path from parameter, env var, or fallback locations."""
    if custom_path:
        return Path(custom_path)
    env_path = os.getenv("GMAIL_CREDENTIALS_PATH")
    if env_path:
        return Path(env_path)
    if Path("data/credentials.json").exists():
        return Path("data/credentials.json")
    return DEFAULT_CREDENTIALS_FILE


def resolve_token_path(custom_path: Path | str | None = None) -> Path:
    """Resolve token file path from parameter, env var, or fallback locations."""
    if custom_path:
        return Path(custom_path)
    env_path = os.getenv("GMAIL_TOKEN_PATH")
    if env_path:
        return Path(env_path)
    if Path("data/token.json").exists():
        return Path("data/token.json")
    return DEFAULT_TOKEN_FILE


class GmailService:
    """Manages Google OAuth 2.0 authorization and Gmail API message retrieval."""

    def __init__(
        self,
        credentials_path: Path | str | None = None,
        token_path: Path | str | None = None,
    ) -> None:
        self._credentials_path = Path(credentials_path) if credentials_path else None
        self._token_path = Path(token_path) if token_path else None

    @property
    def credentials_path(self) -> Path:
        """Dynamically resolve Google OAuth credentials file path."""
        return resolve_credentials_path(self._credentials_path)

    @credentials_path.setter
    def credentials_path(self, path: Path | str | None) -> None:
        self._credentials_path = Path(path) if path else None

    @credentials_path.deleter
    def credentials_path(self) -> None:
        self._credentials_path = None

    @property
    def token_path(self) -> Path:
        """Dynamically resolve Google OAuth token file path."""
        return resolve_token_path(self._token_path)

    @token_path.setter
    def token_path(self, path: Path | str | None) -> None:
        self._token_path = Path(path) if path else None

    @token_path.deleter
    def token_path(self) -> None:
        self._token_path = None

    def load_client_config(self) -> dict[str, Any]:
        """Load client credentials from credentials.json."""
        if not self.credentials_path.exists():
            raise FileNotFoundError(
                f"Credentials file not found at {self.credentials_path.resolve()}"
            )

        with open(self.credentials_path, encoding="utf-8") as f:
            data = json.load(f)

        # Standard Google credentials structure (either 'web' or 'installed')
        config = data.get("web") or data.get("installed")
        if not config:
            raise ValueError(
                "Invalid credentials.json structure: missing 'web' or 'installed' root key."
            )

        return cast(dict[str, Any], config)

    def get_authorization_url(self, redirect_uri: str) -> str:
        """Generate Google OAuth 2.0 consent page URL."""
        config = self.load_client_config()
        client_id = config["client_id"]
        auth_uri = config.get(
            "auth_uri", "https://accounts.google.com/o/oauth2/v2/auth"
        )

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": GMAIL_SCOPE,
            "access_type": "offline",
            "prompt": "consent",
        }
        return f"{auth_uri}?{urllib.parse.urlencode(params)}"

    def exchange_code_for_tokens(self, code: str, redirect_uri: str) -> dict[str, Any]:
        """Exchange authorization code for access and refresh tokens."""
        config = self.load_client_config()
        token_uri = config.get("token_uri", "https://oauth2.googleapis.com/token")

        payload = {
            "code": code,
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        }

        response = requests.post(token_uri, data=payload, timeout=15)
        if response.status_code != 200:
            logger.error("Token exchange failed: %s", response.text)
            raise RuntimeError(f"Google Token Exchange Failed: {response.text}")

        token_data: dict[str, Any] = response.json()
        self.save_tokens(token_data)
        return token_data

    def save_tokens(self, token_data: dict[str, Any]) -> None:
        """Save token JSON payload to token.json."""
        with open(self.token_path, "w", encoding="utf-8") as f:
            json.dump(token_data, f, indent=2)

    def load_tokens(self) -> dict[str, Any] | None:
        """Load stored OAuth token from token.json if present."""
        if not self.token_path.exists():
            return None
        try:
            with open(self.token_path, encoding="utf-8") as f:
                return cast(dict[str, Any] | None, json.load(f))
        except Exception as e:
            logger.warning("Failed to load token file: %s", e)
            return None

    def refresh_access_token(self, refresh_token: str) -> dict[str, Any]:
        """Refresh expired access token using stored refresh token."""
        config = self.load_client_config()
        token_uri = config.get("token_uri", "https://oauth2.googleapis.com/token")

        payload = {
            "client_id": config["client_id"],
            "client_secret": config["client_secret"],
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        }

        response = requests.post(token_uri, data=payload, timeout=15)
        if response.status_code != 200:
            logger.error("Token refresh failed: %s", response.text)
            raise RuntimeError(f"Token refresh failed: {response.text}")

        new_tokens = response.json()
        existing = self.load_tokens() or {}
        existing.update(new_tokens)
        self.save_tokens(existing)
        return existing

    def get_valid_access_token(self) -> str | None:
        """Retrieve a valid access token, refreshing if necessary."""
        tokens = self.load_tokens()
        if not tokens:
            return None

        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")

        if not access_token:
            return None

        # Test token validity against Google userinfo API
        headers = {"Authorization": f"Bearer {access_token}"}
        res = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers=headers,
            timeout=5,
        )
        if res.status_code == 200:
            return cast(str, access_token)

        # Token expired; try refreshing if refresh_token exists
        if refresh_token:
            try:
                refreshed = self.refresh_access_token(refresh_token)
                return cast(str | None, refreshed.get("access_token"))
            except Exception as e:
                logger.error("Failed to auto-refresh token: %s", e)

        return None

    def fetch_last_10_emails(self) -> list[dict[str, Any]]:
        """Fetch the latest 10 emails from user's Gmail inbox."""
        access_token = self.get_valid_access_token()
        if not access_token:
            raise PermissionError("Gmail account is not connected or token expired.")

        headers = {"Authorization": f"Bearer {access_token}"}

        # 1. Fetch message list (max 10)
        list_url = (
            "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=10"
        )
        res = requests.get(list_url, headers=headers, timeout=15)
        if res.status_code != 200:
            raise RuntimeError(f"Failed to fetch Gmail message list: {res.text}")

        msg_list_data = res.json()
        messages = msg_list_data.get("messages", [])

        emails: list[dict[str, Any]] = []

        for msg in messages:
            msg_id = msg["id"]
            detail_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full"
            msg_res = requests.get(detail_url, headers=headers, timeout=15)
            if msg_res.status_code != 200:
                continue

            msg_data = msg_res.json()
            payload = msg_data.get("payload", {})
            headers_list = payload.get("headers", [])

            # Extract header values
            header_map = {}
            for h in headers_list:
                name = h.get("name", "").lower()
                header_map[name] = h.get("value", "")

            sender = header_map.get("from", "Unknown Sender")
            subject = header_map.get("subject", "(No Subject)")
            date_str = header_map.get("date", "")
            snippet = msg_data.get("snippet", "")

            # Extract body content
            body_text = self._extract_body(payload) or snippet

            emails.append(
                {
                    "id": msg_id,
                    "thread_id": msg_data.get("threadId", ""),
                    "sender": sender,
                    "subject": subject,
                    "date": date_str,
                    "snippet": snippet,
                    "body": body_text,
                }
            )

        return emails

    def _extract_body(self, payload: dict[str, Any]) -> str:
        """Extract text/plain or text/html body from message payload structure."""

        def decode_part(part: dict[str, Any]) -> str:
            body_data = part.get("body", {}).get("data", "")
            if not body_data:
                return ""
            try:
                # Base64URL decode
                padding = "=" * (-len(body_data) % 4)
                decoded = base64.urlsafe_b64decode(body_data + padding).decode(
                    "utf-8", errors="replace"
                )
                return decoded
            except Exception:
                return ""

        # Direct body on main payload
        main_body = decode_part(payload)
        if main_body:
            return main_body

        # Check payload parts recursively
        parts = payload.get("parts", [])
        for part in parts:
            mime_type = part.get("mimeType", "")
            if mime_type == "text/plain":
                part_text = decode_part(part)
                if part_text:
                    return part_text
            elif mime_type == "text/html":
                part_html = decode_part(part)
                if part_html:
                    return part_html
            elif "parts" in part:
                sub_body = self._extract_body(part)
                if sub_body:
                    return sub_body

        return ""


# Singleton instance
gmail_service = GmailService()

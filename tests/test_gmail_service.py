"""Unit tests verifying GmailService and Google OAuth endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.services.gmail_service import GmailService


@pytest.fixture
def mock_credentials_file(tmp_path: Path) -> Path:
    """Create a temporary mock credentials.json file."""
    creds_data = {
        "web": {
            "client_id": "test-client-id.apps.googleusercontent.com",
            "project_id": "test-project",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_secret": "test-client-secret",
            "redirect_uris": ["http://localhost:8000/auth/google/callback"],
        }
    }
    creds_file = tmp_path / "credentials.json"
    with open(creds_file, "w", encoding="utf-8") as f:
        json.dump(creds_data, f)
    return creds_file


def test_gmail_service_auth_url_generation(mock_credentials_file: Path) -> None:
    """Verify authorization URL is properly constructed."""
    token_file = mock_credentials_file.parent / "token.json"
    service = GmailService(
        credentials_path=mock_credentials_file, token_path=token_file
    )

    url = service.get_authorization_url("http://localhost:8000/auth/google/callback")
    assert "https://accounts.google.com/o/oauth2/auth" in url
    assert "test-client-id.apps.googleusercontent.com" in url
    assert "gmail.readonly" in url


@patch("requests.post")
def test_gmail_service_token_exchange(
    mock_post: MagicMock, mock_credentials_file: Path
) -> None:
    """Verify authorization code exchange for tokens."""
    token_file = mock_credentials_file.parent / "token.json"
    service = GmailService(
        credentials_path=mock_credentials_file, token_path=token_file
    )

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "access_token": "mock-access-token",
        "refresh_token": "mock-refresh-token",
        "expires_in": 3600,
    }
    mock_post.return_value = mock_response

    tokens = service.exchange_code_for_tokens(
        "mock-code", "http://localhost:8000/auth/google/callback"
    )
    assert tokens["access_token"] == "mock-access-token"
    assert token_file.exists()


def test_gmail_status_endpoint() -> None:
    """Verify /api/v1/gmail/status endpoint returns valid status."""
    client = TestClient(app)
    response = client.get("/api/v1/gmail/status")
    assert response.status_code == 200
    data = response.json()
    assert "connected" in data
    assert "credentials_configured" in data


def test_gmail_path_resolution_env_vars(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify GMAIL_CREDENTIALS_PATH and GMAIL_TOKEN_PATH env vars take precedence."""
    from src.services.gmail_service import resolve_credentials_path, resolve_token_path

    custom_creds = tmp_path / "custom_creds.json"
    custom_token = tmp_path / "custom_token.json"
    monkeypatch.setenv("GMAIL_CREDENTIALS_PATH", str(custom_creds))
    monkeypatch.setenv("GMAIL_TOKEN_PATH", str(custom_token))

    assert resolve_credentials_path() == custom_creds
    assert resolve_token_path() == custom_token


def test_gmail_path_resolution_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify fallback path resolution when no custom path or env var is set."""
    from src.services.gmail_service import resolve_credentials_path, resolve_token_path

    monkeypatch.delenv("GMAIL_CREDENTIALS_PATH", raising=False)
    monkeypatch.delenv("GMAIL_TOKEN_PATH", raising=False)

    creds_path = resolve_credentials_path()
    token_path = resolve_token_path()
    assert creds_path in [Path("data/credentials.json"), Path("credentials.json")]
    assert token_path in [Path("data/token.json"), Path("token.json")]


def test_gmail_service_missing_credentials_raises_safe_error(tmp_path: Path) -> None:
    """Verify missing credentials file raises FileNotFoundError without logging secrets."""
    non_existent_creds = tmp_path / "does_not_exist.json"
    service = GmailService(credentials_path=non_existent_creds)
    with pytest.raises(FileNotFoundError) as exc_info:
        service.load_client_config()
    assert "Credentials file not found" in str(exc_info.value)


def test_gmail_disconnect_endpoint(tmp_path: Path) -> None:
    """Verify /api/v1/gmail/disconnect removes token file."""
    fake_token = tmp_path / "token.json"
    fake_token.write_text('{"access_token": "abc"}', encoding="utf-8")
    assert fake_token.exists()

    with patch("src.services.gmail_service.gmail_service.token_path", fake_token):
        client = TestClient(app)
        response = client.post("/api/v1/gmail/disconnect")
        assert response.status_code == 200
        assert response.json() == {"status": "disconnected"}
        assert not fake_token.exists()

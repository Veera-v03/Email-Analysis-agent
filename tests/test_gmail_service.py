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

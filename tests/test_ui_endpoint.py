"""Unit tests for the Cyber Security UI and demo auth endpoints."""

from __future__ import annotations

import tempfile
from collections.abc import Generator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.database.db_client import db_client


@pytest.fixture(autouse=True)
def setup_test_db() -> Generator[None]:
    """Redirect global db_client path to a temporary database for test duration."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        original_db_path = db_client.db_path
        db_file = Path(tmp_dir) / "test_ui.db"

        db_client.db_path = str(db_file)
        db_client._initialize_db()

        yield

        db_client.db_path = original_db_path


def test_cyber_ui_endpoint_returns_html() -> None:
    """Verify root / route serves the Cyber Security UI HTML."""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    assert "SCAMSHIELD" in response.text
    assert "Cyber Threat Command Center" in response.text
    assert "CYBER SECURITY" in response.text


def test_demo_token_endpoint() -> None:
    """Verify POST /api/v1/auth/demo-token issues valid tokens."""
    client = TestClient(app)
    response = client.post("/api/v1/auth/demo-token")
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

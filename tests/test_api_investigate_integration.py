"""Integration tests verifying the FastAPI `/api/v1/investigate` endpoint with real wiring."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Generator
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.config.enterprise_config import settings
from src.database.db_client import db_client
from src.database.repositories import (
    LegacyUserRepository as UserRepository,
)
from src.database.repositories import (
    OrganizationRepository,
)
from src.security.auth import create_jwt_token, hash_password


class MockResponse:
    """Mock HTTP response matching requests API."""

    def __init__(self, json_data: dict[str, Any], status_code: int = 200) -> None:
        self.json_data = json_data
        self.status_code = status_code
        self.text = json.dumps(json_data)

    def json(self) -> dict[str, Any]:
        return self.json_data


@pytest.fixture(autouse=True)
def setup_test_db() -> Generator[None]:
    """Redirect global db_client path to a temporary database for test duration."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        original_db_path = db_client.db_path
        db_file = Path(tmp_dir) / "test_enterprise.db"

        # Override db_client and initialize schema
        db_client.db_path = str(db_file)
        db_client._initialize_db()

        yield

        # Restore db_path
        db_client.db_path = original_db_path


def test_api_investigate_integration_success() -> None:
    """Verify investigation endpoint with real wiring and mocked LLM calls."""
    # 1. Setup organization in temp db
    org_repo = OrganizationRepository(db_client)
    org = org_repo.create("Test Enterprise Corp", org_id="org_test_123")

    # 2. Setup user in temp db to satisfy audit_logs foreign key constraint
    user_repo = UserRepository(db_client)
    user = user_repo.create(
        org_id=org["id"],
        username="test_analyst",
        password_hash=hash_password("dummy_password"),
        roles=["analyst"],
        user_id="user_test_999",
    )

    # 3. Create valid auth JWT token
    claims = {
        "sub": user["id"],
        "org_id": org["id"],
        "roles": ["analyst"],
    }
    jwt_token = create_jwt_token(claims)

    # 4. Configure dummy API key override for GroqProvider validation check
    settings.set_override("GROQ_API_KEY", "dummy-key-for-test")

    # 5. Mock requests.post to simulate iterative LLM planning calls
    call_count = 0

    def mock_post(url: str, *args: Any, **kwargs: Any) -> MockResponse:
        nonlocal call_count
        call_count += 1

        if call_count == 1:
            # First planning prompt: propose parsing the email
            plan_content = json.dumps(
                {
                    "goal": "Verify email safety",
                    "strategy": "targeted",
                    "steps": [
                        {
                            "step_id": "step_parse",
                            "tool": "parser_tool",
                            "priority": 1,
                            "reason": "First parse",
                        }
                    ],
                    "confidence": 0.95,
                }
            )
        else:
            # Subsequent planning prompt: complete the loop
            plan_content = json.dumps(
                {
                    "goal": "Finished",
                    "strategy": "targeted",
                    "steps": [],
                    "confidence": 0.99,
                }
            )

        response_data = {
            "choices": [{"message": {"content": plan_content}}],
            "usage": {"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35},
            "id": f"chatcmpl-test-{call_count}",
            "model": "llama3-8b-8192",
            "object": "chat.completion",
        }
        return MockResponse(response_data)

    client = TestClient(app)

    # Run endpoint request with patched network request
    with mock.patch("requests.post", side_effect=mock_post):
        payload = {
            "subject": "Urgent Action Required",
            "sender": "spammer@malicious.domain.com",
            "body": "Dear customer, please verify your credentials.",
        }
        headers = {
            "Authorization": f"Bearer {jwt_token}",
        }
        response = client.post("/api/v1/investigate", json=payload, headers=headers)

        assert response.status_code == 200
        res_json = response.json()

        # Check verdict structure and content
        assert "investigation_id" in res_json
        assert res_json["status"] == "completed"
        assert "verdict" in res_json
        assert "confidence" in res_json
        assert "risk_level" in res_json
        assert "report" in res_json

        # Check report fields
        report = res_json["report"]
        assert report["classification"] is not None
        assert "parser_tool" in report["executed_tools"]

        memory_response = client.get(
            "/api/v1/memory/search",
            params={"q": "Urgent Action Required"},
            headers=headers,
        )
        assert memory_response.status_code == 200
        assert any(
            item["record"].get("sender") == "spammer@malicious.domain.com"
            for item in memory_response.json()
        )


def test_api_investigate_missing_api_key_fails() -> None:
    """Verify that investigation endpoint fails with 500 CONFIG_ERROR when GROQ_API_KEY is empty."""
    org_repo = OrganizationRepository(db_client)
    org = org_repo.create("Test Enterprise Corp 2", org_id="org_test_456")

    user_repo = UserRepository(db_client)
    user = user_repo.create(
        org_id=org["id"],
        username="test_analyst_2",
        password_hash=hash_password("dummy_password"),
        roles=["analyst"],
        user_id="user_test_888",
    )

    claims = {
        "sub": user["id"],
        "org_id": org["id"],
        "roles": ["analyst"],
    }
    jwt_token = create_jwt_token(claims)

    # Explicitly clear GROQ_API_KEY override
    settings.set_override("GROQ_API_KEY", None)

    client = TestClient(app)
    payload = {
        "subject": "Urgent Action Required",
        "sender": "spammer@malicious.domain.com",
        "body": "Dear customer, please verify your credentials.",
    }
    headers = {
        "Authorization": f"Bearer {jwt_token}",
    }

    with mock.patch.dict("os.environ", {"GROQ_API_KEY": ""}, clear=True):
        response = client.post("/api/v1/investigate", json=payload, headers=headers)

    assert response.status_code == 500
    res_json = response.json()
    assert res_json["error"]["code"] == "CONFIG_ERROR"
    assert "GROQ_API_KEY is not configured" in res_json["error"]["message"]

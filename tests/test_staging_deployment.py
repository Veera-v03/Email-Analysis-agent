"""Integration and contract tests for Staging Deployment, Liveness, and Readiness endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.common.redis_client import AsyncRedisClient, InMemoryRedisClient


@pytest.fixture
def client() -> TestClient:
    return TestClient(app)


def test_liveness_health_endpoint(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "timestamp" in data
    assert "system" in data


def test_readiness_probe_endpoint_structure(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert "timestamp" in data
    assert "checks" in data
    checks = data["checks"]
    assert "database" in checks
    assert "redis" in checks
    assert "pgvector" in checks


@pytest.mark.asyncio
async def test_async_redis_client_ping_success() -> None:
    cli = AsyncRedisClient(fallback_to_memory=True)
    # Mock underlying connection ping
    mock_conn = AsyncMock()
    mock_conn.ping.return_value = True
    cli._redis_conn = mock_conn

    res = await cli.ping()
    assert res is True


@pytest.mark.asyncio
async def test_async_redis_client_ping_failure_returns_false() -> None:
    cli = AsyncRedisClient(redis_url="redis://invalid-host:6379/0", fallback_to_memory=True, timeout_sec=0.1)
    res = await cli.ping()
    assert res is False
    assert cli._is_degraded is True


def test_readiness_reports_connected_on_successful_redis_ping(client: TestClient) -> None:
    with patch("src.common.redis_client.AsyncRedisClient.ping", new_callable=AsyncMock) as mock_ping:
        mock_ping.return_value = True
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["checks"]["redis"] == "connected"


def test_readiness_reports_degraded_on_failed_redis_ping(client: TestClient) -> None:
    with patch("src.common.redis_client.AsyncRedisClient.ping", new_callable=AsyncMock) as mock_ping:
        mock_ping.return_value = False
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["checks"]["redis"] == "degraded_in_memory"


def test_metrics_endpoint(client: TestClient) -> None:
    response = client.get("/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "active_processes" in data
    assert "database_connected" in data


def test_groq_model_configuration_and_provider_usage() -> None:
    from src.config.enterprise_config import settings
    from src.planner.providers.groq.groq_provider import GroqProvider

    # Default configured model is openai/gpt-oss-20b, never obsolete llama-3.1-8b-instant
    provider = GroqProvider(api_key="test-key")
    assert provider._default_model == "openai/gpt-oss-20b"
    assert provider._default_model != "llama-3.1-8b-instant"

    # Respects runtime override or explicit default_model
    custom_provider = GroqProvider(api_key="test-key", default_model="qwen/qwen3.6-27b")
    assert custom_provider._default_model == "qwen/qwen3.6-27b"

    # Respects settings override
    settings.set_override("GROQ_MODEL", "openai/gpt-oss-120b")
    try:
        env_provider = GroqProvider(api_key="test-key")
        assert env_provider._default_model == "openai/gpt-oss-120b"
    finally:
        settings._overrides.pop("GROQ_MODEL", None)

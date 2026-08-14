"""OpsEngine central manager for Module 18 Enterprise Operations."""

from typing import Any

from src.config.logging import get_logger
from src.ops.connectors.ms_graph_adapter import MicrosoftGraphAdapter
from src.ops.connectors.okta_adapter import OktaAdapter
from src.ops.connectors.panos_adapter import PANOSAdapter
from src.ops.postgres_client import PostgresDatabaseClient
from src.ops.prometheus_exporter import PrometheusMetricsExporter
from src.ops.redis_bus import RedisStreamsEventBus
from src.ops.redis_cache import RedisReputationCache

logger = get_logger("scamon.ops.engine")


class OpsEngine:
    """Central engine managing PostgreSQL storage, Redis infrastructure, connectors, and telemetry."""

    def __init__(
        self,
        postgres_url: str | None = None,
        redis_url: str | None = None,
    ) -> None:
        self.db_client = PostgresDatabaseClient(postgres_url=postgres_url)
        self.event_bus = RedisStreamsEventBus(redis_url=redis_url)
        self.reputation_cache = RedisReputationCache(redis_url=redis_url)
        self.metrics_exporter = PrometheusMetricsExporter()
        self.ms_graph_adapter = MicrosoftGraphAdapter()
        self.okta_adapter = OktaAdapter()
        self.panos_adapter = PANOSAdapter()

    def get_status_summary(self) -> dict[str, Any]:
        """Return operational status summary for health check and diagnostics."""
        return {
            "postgres_active": self.db_client.is_postgres,
            "redis_bus_active": self.event_bus.is_redis,
            "reputation_cache_ttl": self.reputation_cache.ttl_seconds,
            "adapters": [
                self.ms_graph_adapter.adapter_name,
                self.okta_adapter.adapter_name,
                self.panos_adapter.adapter_name,
            ],
        }

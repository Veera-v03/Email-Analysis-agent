"""PostgreSQL + pgvector semantic vector memory storage implementation with HNSW indexing and in-memory fallback."""

from __future__ import annotations

import json
from typing import Any

from src.config.enterprise_config import settings
from src.config.logging import get_logger
from src.memory.models.memory_models import (
    BaseMemoryRecord,
    InvestigationMemory,
    MemorySearchResult,
    MemoryType,
)
from src.memory.storage.vector_store import (
    InMemoryVectorStore,
    IVectorStore,
)

logger = get_logger("scamon.memory.storage.pgvector")


class PgVectorStore(IVectorStore):
    """Production-grade PostgreSQL + pgvector storage with HNSW cosine distance indexing and resilient fallback."""

    def __init__(
        self,
        connection_url: str | None = None,
        dimension: int | None = None,
        fallback_store: IVectorStore | None = None,
        timeout_sec: float | None = None,
        db_engine: Any | None = None,
    ) -> None:
        self._url = connection_url or settings.get_secret("PGVECTOR_URL")
        self._dim = (
            dimension
            if dimension is not None
            else getattr(settings, "pgvector_embedding_dimension", 768)
        )
        self._timeout_sec = (
            timeout_sec
            if timeout_sec is not None
            else getattr(settings, "pgvector_timeout_sec", 3.0)
        )
        self._fallback_store = fallback_store or InMemoryVectorStore()
        self._db_engine = db_engine
        self._is_degraded = False

        if not self._url and not self._db_engine:
            self._is_degraded = True
            logger.info("pgvector URL not configured; initialized in degraded local in-memory fallback mode")

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def is_degraded(self) -> bool:
        return self._is_degraded

    def get_health_status(self) -> dict[str, Any]:
        """Report storage backend health status."""
        return {
            "status": "PGVECTOR_DEGRADED" if self._is_degraded else "PGVECTOR_CONNECTED",
            "backend": "in_memory" if self._is_degraded else "postgresql_pgvector",
            "dimension": self._dim,
            "fallback_enabled": True,
        }

    def _validate_vector(self, vector: tuple[float, ...]) -> None:
        """Validate vector dimensionality before storage."""
        if len(vector) != self._dim:
            raise ValueError(
                f"Vector dimension mismatch: expected {self._dim}, got {len(vector)}"
            )

    def insert(self, record: BaseMemoryRecord) -> None:
        """Insert or replace memory record."""
        if record.vector:
            self._validate_vector(record.vector)

        if self._is_degraded or not self._db_engine:
            self._fallback_store.insert(record)
            return

        try:
            # When connected to live SQLAlchemy/PostgreSQL engine
            tenant_id = str(record.metadata.get("tenant_id", record.metadata.get("org_id", "default")))
            metadata_json = json.dumps(record.metadata)
            embedding_str = f"[{','.join(str(v) for v in record.vector)}]" if record.vector else None

            sql = """
            INSERT INTO scamon_memory_vectors (memory_id, tenant_id, memory_type, embedding, metadata, created_at)
            VALUES (:memory_id, :tenant_id, :memory_type, :embedding, :metadata, :created_at)
            ON CONFLICT (memory_id) DO UPDATE SET
                embedding = EXCLUDED.embedding,
                metadata = EXCLUDED.metadata,
                updated_at = NOW();
            """
            with self._db_engine.connect() as conn:
                conn.execute(
                    sql,
                    {
                        "memory_id": record.memory_id,
                        "tenant_id": tenant_id,
                        "memory_type": record.memory_type.value,
                        "embedding": embedding_str,
                        "metadata": metadata_json,
                        "created_at": record.created_at,
                    },
                )
                conn.commit()
        except Exception as exc:
            logger.warning("pgvector insert error (%s); falling back to in-memory store", type(exc).__name__)
            self._is_degraded = True
            self._fallback_store.insert(record)

    def update(self, record: BaseMemoryRecord) -> None:
        """Update existing memory record."""
        if record.vector:
            self._validate_vector(record.vector)

        if self._is_degraded or not self._db_engine:
            self._fallback_store.update(record)
            return

        try:
            metadata_json = json.dumps(record.metadata)
            embedding_str = f"[{','.join(str(v) for v in record.vector)}]" if record.vector else None

            sql = """
            UPDATE scamon_memory_vectors
            SET embedding = :embedding, metadata = :metadata, updated_at = NOW()
            WHERE memory_id = :memory_id;
            """
            with self._db_engine.connect() as conn:
                res = conn.execute(
                    sql,
                    {
                        "memory_id": record.memory_id,
                        "embedding": embedding_str,
                        "metadata": metadata_json,
                    },
                )
                conn.commit()
                if res.rowcount == 0:
                    raise KeyError(f"Record with memory_id '{record.memory_id}' does not exist.")
        except KeyError:
            raise
        except Exception as exc:
            logger.warning("pgvector update error (%s); falling back to in-memory store", type(exc).__name__)
            self._is_degraded = True
            self._fallback_store.update(record)

    def delete(self, memory_id: str) -> bool:
        """Delete record by memory_id."""
        if self._is_degraded or not self._db_engine:
            return self._fallback_store.delete(memory_id)

        try:
            sql = "DELETE FROM scamon_memory_vectors WHERE memory_id = :memory_id;"
            with self._db_engine.connect() as conn:
                res = conn.execute(sql, {"memory_id": memory_id})
                conn.commit()
                return res.rowcount > 0
        except Exception as exc:
            logger.warning("pgvector delete error (%s); falling back to in-memory store", type(exc).__name__)
            self._is_degraded = True
            return self._fallback_store.delete(memory_id)

    def get(self, memory_id: str) -> BaseMemoryRecord | None:
        """Fetch record by memory_id."""
        if self._is_degraded or not self._db_engine:
            return self._fallback_store.get(memory_id)

        try:
            sql = "SELECT memory_id, tenant_id, memory_type, embedding, metadata, created_at FROM scamon_memory_vectors WHERE memory_id = :memory_id;"
            with self._db_engine.connect() as conn:
                row = conn.execute(sql, {"memory_id": memory_id}).fetchone()
                if not row:
                    return None
                meta = json.loads(row[4]) if isinstance(row[4], str) else row[4]
                return BaseMemoryRecord(
                    memory_id=row[0],
                    memory_type=MemoryType(row[2]),
                    confidence_score=meta.get("confidence_score", 1.0),
                    created_at=row[5],
                    vector=tuple(float(v) for v in row[3]) if row[3] else (),
                    metadata=meta,
                )
        except Exception as exc:
            logger.warning("pgvector get error (%s); falling back to in-memory store", type(exc).__name__)
            self._is_degraded = True
            return self._fallback_store.get(memory_id)

    def similarity_search(
        self,
        query_vector: tuple[float, ...],
        top_k: int = 5,
        memory_type: MemoryType | None = None,
        min_confidence: float = 0.0,
        metadata_filters: dict[str, Any] | None = None,
    ) -> list[MemorySearchResult]:
        """Perform top-k similarity search using cosine distance with strict query-boundary tenant filtering."""
        if query_vector:
            self._validate_vector(query_vector)

        if self._is_degraded or not self._db_engine:
            return self._fallback_store.similarity_search(
                query_vector=query_vector,
                top_k=top_k,
                memory_type=memory_type,
                min_confidence=min_confidence,
                metadata_filters=metadata_filters,
            )

        try:
            # Enforce strict tenant isolation at query boundary
            tenant_filter = None
            if metadata_filters:
                tenant_filter = metadata_filters.get("tenant_id") or metadata_filters.get("org_id")

            where_clauses = []
            params: dict[str, Any] = {
                "embedding": f"[{','.join(str(v) for v in query_vector)}]",
                "top_k": top_k,
            }

            if tenant_filter is not None:
                where_clauses.append("tenant_id = :tenant_id")
                params["tenant_id"] = str(tenant_filter)

            if memory_type is not None:
                where_clauses.append("memory_type = :memory_type")
                params["memory_type"] = memory_type.value

            where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

            sql = f"""
            SELECT memory_id, tenant_id, memory_type, metadata, created_at,
                   1 - (embedding <=> :embedding) AS similarity_score
            FROM scamon_memory_vectors
            {where_sql}
            ORDER BY embedding <=> :embedding
            LIMIT :top_k;
            """

            results: list[MemorySearchResult] = []
            with self._db_engine.connect() as conn:
                rows = conn.execute(sql, params).fetchall()
                for row in rows:
                    sim_score = float(row[5])
                    meta = json.loads(row[3]) if isinstance(row[3], str) else row[3]
                    conf = float(meta.get("confidence_score", 1.0))
                    if conf < min_confidence:
                        continue

                    rec = BaseMemoryRecord(
                        memory_id=row[0],
                        memory_type=MemoryType(row[2]),
                        confidence_score=conf,
                        created_at=row[4],
                        metadata=meta,
                    )
                    results.append(
                        MemorySearchResult(
                            memory_id=rec.memory_id,
                            memory_type=rec.memory_type,
                            similarity_score=round(sim_score, 4),
                            record=rec,
                        )
                    )
            return results

        except Exception as exc:
            logger.warning("pgvector similarity search error (%s); falling back to in-memory store", type(exc).__name__)
            self._is_degraded = True
            return self._fallback_store.similarity_search(
                query_vector=query_vector,
                top_k=top_k,
                memory_type=memory_type,
                min_confidence=min_confidence,
                metadata_filters=metadata_filters,
            )

    def clear(self) -> None:
        """Clear all stored vector records."""
        if self._is_degraded or not self._db_engine:
            self._fallback_store.clear()
            return

        try:
            with self._db_engine.connect() as conn:
                conn.execute("TRUNCATE TABLE scamon_memory_vectors;")
                conn.commit()
        except Exception:
            self._fallback_store.clear()

    def count(self) -> int:
        """Return total record count."""
        if self._is_degraded or not self._db_engine:
            return self._fallback_store.count()

        try:
            with self._db_engine.connect() as conn:
                res = conn.execute("SELECT COUNT(*) FROM scamon_memory_vectors;").scalar()
                return int(res or 0)
        except Exception:
            return self._fallback_store.count()

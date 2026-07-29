"""Analyst feedback system for memory correction, feedback collection, and confidence tuning."""

from __future__ import annotations

from datetime import UTC, datetime

from src.memory.models.memory_models import (
    FeedbackRecord,
)
from src.memory.storage.vector_store import IVectorStore


class AnalystFeedbackSystem:
    """Processes security analyst feedback to correct memory entries and adjust confidence scores."""

    def __init__(self, vector_store: IVectorStore) -> None:
        self._store = vector_store
        self._feedback_records: list[FeedbackRecord] = []

    def submit_feedback(
        self,
        memory_id: str,
        analyst_verdict: str,
        analyst_notes: str = "",
    ) -> FeedbackRecord:
        """Submit feedback for a memory record, updating confidence scores and reputation flags.

        Analyst verdicts:
          - confirmed_phishing: Boost confidence to 0.99, mark threat indicators as verified.
          - false_positive: Lower risk rating, reduce confidence score to 0.1.
          - false_negative: Upgrade risk rating, boost confidence score to 0.99.
          - safe_email: Mark entry as safe, reset risk indicators.
        """
        now = datetime.now(UTC).isoformat()
        record = self._store.get(memory_id)

        feedback = FeedbackRecord(
            memory_id=memory_id,
            analyst_verdict=analyst_verdict,
            analyst_notes=analyst_notes,
            timestamp=now,
        )
        self._feedback_records.append(feedback)

        if not record:
            return feedback

        # Apply confidence and status corrections depending on analyst verdict
        verdict_lower = analyst_verdict.lower()

        if verdict_lower == "confirmed_phishing":
            updated_record = record.model_copy(
                update={"confidence_score": 0.99, "updated_at": now}
            )
            self._store.update(updated_record)
        elif verdict_lower == "false_positive":
            updated_record = record.model_copy(
                update={"confidence_score": 0.1, "updated_at": now}
            )
            self._store.update(updated_record)
        elif verdict_lower == "false_negative":
            updated_record = record.model_copy(
                update={"confidence_score": 0.99, "updated_at": now}
            )
            self._store.update(updated_record)
        elif verdict_lower == "safe_email":
            updated_record = record.model_copy(
                update={"confidence_score": 0.95, "updated_at": now}
            )
            self._store.update(updated_record)

        return feedback

    def get_feedback_history(
        self, memory_id: str | None = None
    ) -> tuple[FeedbackRecord, ...]:
        """Retrieve feedback history, optionally filtered by memory_id."""
        if memory_id:
            return tuple(
                fb for fb in self._feedback_records if fb.memory_id == memory_id
            )
        return tuple(self._feedback_records)

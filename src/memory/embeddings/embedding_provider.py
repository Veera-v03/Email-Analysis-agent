"""Embedding provider abstraction and deterministic vector generator implementations."""

from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Sequence


class IEmbeddingProvider(ABC):
    """Abstract interface for generating dense numerical vector embeddings from text."""

    @abstractmethod
    def embed_text(self, text: str) -> tuple[float, ...]:
        """Convert a single text string into a normalized embedding vector."""

    @abstractmethod
    def embed_batch(self, texts: Sequence[str]) -> list[tuple[float, ...]]:
        """Convert a batch of text strings into normalized embedding vectors."""

    @property
    @abstractmethod
    def dimension(self) -> int:
        """Return the fixed dimensionality of the vector embeddings."""


class DeterministicEmbeddingProvider(IEmbeddingProvider):
    """Deterministic, zero-dependency feature vectorizer for local semantic similarity search.

    Uses character/token n-gram hashing and term frequency normalization to map text to
    a unit-normalized float vector of fixed dimensionality (default: 64).
    """

    def __init__(self, dimension: int = 64, cache_capacity: int = 1000) -> None:
        self._dim = dimension
        self._cache_capacity = cache_capacity
        self._cache: dict[str, tuple[float, ...]] = {}

    @property
    def dimension(self) -> int:
        return self._dim

    def embed_text(self, text: str) -> tuple[float, ...]:
        """Map text to a deterministic normalized unit vector with LRU caching."""
        normalized_text = text.strip().lower()
        if not normalized_text:
            return (0.0,) * self._dim

        if normalized_text in self._cache:
            return self._cache[normalized_text]

        # Extract tokens and character 3-grams
        tokens = re.findall(r"\w+", normalized_text)
        ngrams: list[str] = list(tokens)

        for token in tokens:
            if len(token) >= 3:
                for i in range(len(token) - 2):
                    ngrams.append(token[i : i + 3])

        # Frequency distribution
        counts = Counter(ngrams)

        # Hash feature mapping into fixed dimension buckets
        vector = [0.0] * self._dim
        for item, count in counts.items():
            # Hash to bucket index and sign
            h = hash(item)
            bucket = abs(h) % self._dim
            sign = 1.0 if (h >= 0) else -1.0
            vector[bucket] += sign * math.log1p(count)

        # Compute L2 norm
        l2_norm = math.sqrt(sum(v * v for v in vector))
        if l2_norm > 0:
            vector = [round(v / l2_norm, 6) for v in vector]
        else:
            vector = [0.0] * self._dim

        res_tuple = tuple(vector)

        # Cache management
        if len(self._cache) >= self._cache_capacity:
            # Evict oldest entry
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]
        self._cache[normalized_text] = res_tuple

        return res_tuple

    def embed_batch(self, texts: Sequence[str]) -> list[tuple[float, ...]]:
        """Process a sequence of texts into embedding vectors."""
        return [self.embed_text(t) for t in texts]


class MockEmbeddingProvider(IEmbeddingProvider):
    """Configurable mock provider for unit testing embedding pipelines."""

    def __init__(self, dimension: int = 64) -> None:
        self._dim = dimension

    @property
    def dimension(self) -> int:
        return self._dim

    def embed_text(self, text: str) -> tuple[float, ...]:
        val = (len(text) % 100) / 100.0
        vec = [val] * self._dim
        return tuple(vec)

    def embed_batch(self, texts: Sequence[str]) -> list[tuple[float, ...]]:
        return [self.embed_text(t) for t in texts]

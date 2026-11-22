"""Replay protection: cache protocol plus a thread-safe in-memory cache.

Tolerance windows already reject old messages; a replay cache additionally
rejects *resends within the window* by remembering verified message keys.
Implement :class:`ReplayCache` against your own store (Redis, memcached, a
database table) for multi-process deployments.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol

__all__ = ["MemoryReplayCache", "ReplayCache"]


class ReplayCache(Protocol):
    """Minimal interface for replay-protection backends.

    Both methods must be safe to call concurrently. Implementations should
    treat ``ttl_seconds`` as a per-entry expiry hint.
    """

    def seen_within(self, key: str, ttl_seconds: float) -> bool:
        """Return True when ``key`` was remembered less than ``ttl_seconds`` ago."""
        ...

    def remember(self, key: str, ttl_seconds: float) -> None:
        """Record ``key`` so ``seen_within`` returns True for ``ttl_seconds``."""
        ...


class MemoryReplayCache:
    """Single-process, thread-safe in-memory :class:`ReplayCache`.

    Each entry expires ``ttl_seconds`` after it was remembered (the TTL
    given to :meth:`remember`); pruning happens lazily on every operation,
    which keeps the cache bounded under regular traffic. For multi-worker
    deployments (gunicorn/uvicorn workers, serverless) implement
    :class:`ReplayCache` against a shared store instead — process-local
    caches cannot see each other's entries.
    """

    def __init__(self) -> None:
        self._entries: dict[str, tuple[float, float]] = {}  # key -> (recorded_at, ttl)
        self._lock = threading.Lock()

    def seen_within(self, key: str, ttl_seconds: float) -> bool:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            entry = self._entries.get(key)
            if entry is None:
                return False
            recorded_at, _ = entry
            return (now - recorded_at) < ttl_seconds

    def remember(self, key: str, ttl_seconds: float) -> None:
        now = time.monotonic()
        with self._lock:
            self._prune(now)
            self._entries[key] = (now, ttl_seconds)

    def discard(self, key: str) -> None:
        """Explicitly forget one key (e.g. after compensating actions)."""
        with self._lock:
            self._entries.pop(key, None)

    def clear(self) -> None:
        """Forget every cached key."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            self._prune(time.monotonic())
            return len(self._entries)

    def _prune(self, now: float) -> None:
        expired = [
            key for key, (recorded_at, ttl) in self._entries.items() if now - recorded_at >= ttl
        ]
        for key in expired:
            del self._entries[key]

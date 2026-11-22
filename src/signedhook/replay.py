"""Replay protection: cache protocols plus a thread-safe in-memory cache.

Tolerance windows already reject old messages; a replay cache additionally
rejects *resends within the window* by remembering verified message keys.
Implement :class:`ReplayCache` (or the awaitable :class:`AsyncReplayCache`)
against your own store (Redis, memcached, a database table) for
multi-process deployments.
"""

from __future__ import annotations

import threading
import time
from typing import Protocol

from ._errors import ConfigurationError

__all__ = ["AsyncMemoryReplayCache", "AsyncReplayCache", "MemoryReplayCache", "ReplayCache"]


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


class AsyncReplayCache(Protocol):
    """Awaitable twin of :class:`ReplayCache` for asyncio applications.

    Same contract, same semantics — ``seen_within`` / ``remember`` are
    coroutines. Use with :func:`signedhook.verify_with_replay_async` and
    :func:`signedhook.verify_twilio_async`, or pass an implementation to
    the FastAPI dependency, which detects async caches automatically.
    """

    async def seen_within(self, key: str, ttl_seconds: float) -> bool:
        """Return True when ``key`` was remembered less than ``ttl_seconds`` ago."""
        ...

    async def remember(self, key: str, ttl_seconds: float) -> None:
        """Record ``key`` so ``seen_within`` returns True for ``ttl_seconds``."""
        ...


class MemoryReplayCache:
    """Single-process, thread-safe in-memory :class:`ReplayCache`.

    Each entry expires ``ttl_seconds`` after it was remembered (the TTL
    given to :meth:`remember`); pruning happens lazily on every operation.
    Pass ``maxsize`` to bound memory for long-running processes: when the
    cache holds more than ``maxsize`` live entries, the least recently
    remembered key is evicted first (remembering a key again refreshes its
    recency). This is still process-local — workers cannot see each
    other's entries — so multi-worker deployments (gunicorn/uvicorn workers,
    serverless) should use :class:`~signedhook.replay_backends.
    RedisReplayCache` or :class:`~signedhook.replay_backends.
    SQLiteReplayCache` instead.

    Args:
        maxsize: maximum number of live entries (``None`` keeps the cache
            unbounded, relying on TTL pruning alone).

    Raises:
        ConfigurationError: ``maxsize`` is not a positive integer or ``None``.
    """

    def __init__(self, maxsize: int | None = None) -> None:
        invalid = maxsize is not None and (
            not isinstance(maxsize, int) or isinstance(maxsize, bool) or maxsize < 1
        )
        if invalid:
            raise ConfigurationError(f"maxsize must be a positive integer or None, got {maxsize!r}")
        self._maxsize = maxsize
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
            # pop-then-store refreshes recency for keys already remembered
            self._entries.pop(key, None)
            self._entries[key] = (now, ttl_seconds)
            if self._maxsize is not None:
                while len(self._entries) > self._maxsize:
                    oldest = next(iter(self._entries))
                    del self._entries[oldest]

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


class AsyncMemoryReplayCache:
    """Awaitable in-memory :class:`AsyncReplayCache` (single process).

        A thin async façade over the thread-safe :class:`MemoryReplayCache`, so
        asyncio applications get the exact same expiry semantics without
        blocking calls. Sharing the underlying store with sync code is fine:
        pass the same ``MemoryReplayCache`` instance to both. For multi-worker
    deployments use :class:`~signedhook.replay_backends.AsyncRedisReplayCache`
        or bring your own async store.
    """

    def __init__(
        self, inner: MemoryReplayCache | None = None, *, maxsize: int | None = None
    ) -> None:
        self._inner = inner if inner is not None else MemoryReplayCache(maxsize=maxsize)

    async def seen_within(self, key: str, ttl_seconds: float) -> bool:
        return self._inner.seen_within(key, ttl_seconds)

    async def remember(self, key: str, ttl_seconds: float) -> None:
        self._inner.remember(key, ttl_seconds)

    async def discard(self, key: str) -> None:
        """Explicitly forget one key (e.g. after compensating actions)."""
        self._inner.discard(key)

    def __len__(self) -> int:
        return len(self._inner)

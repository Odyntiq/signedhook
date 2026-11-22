"""Shared replay-cache backends for multi-worker deployments.

:class:`~signedhook.replay.MemoryReplayCache` is process-local: workers each
hold their own copy and cannot see each other's entries, so a delivery
replayed to a different worker slips through. The backends here close that
gap while keeping the zero-dependency core intact:

- :class:`RedisReplayCache` — works with any Redis-compatible client
  (redis-py, Valkey, KeyDB and friends); each operation is a single atomic
  Redis command, so workers race safely.
- :class:`SQLiteReplayCache` — stdlib-only shared cache for workers on one
  host: a SQLite file in WAL mode, one connection per worker process,
  cross-process locking handled by SQLite itself.

Both implement the :class:`~signedhook.replay.ReplayCache` protocol and can
be passed to ``verify_with_replay`` / ``verify_twilio`` unchanged.
"""

from __future__ import annotations

import math
import sqlite3
import threading
import time
from collections.abc import Callable
from os import PathLike
from typing import Protocol

from ._errors import ConfigurationError

__all__ = ["RedisReplayCache", "SQLiteReplayCache"]


class _RedisLike(Protocol):
    """The slice of a Redis client the cache relies on.

    Parameters are declared positional-only so any client whose ``set`` /
    ``get`` / ``delete`` methods accept these arguments positionally (all
    Redis-compatible clients do) satisfies the protocol regardless of its
    own parameter names.
    """

    def set(self, key: str, value: str, /, *, ex: int, nx: bool = False) -> object: ...

    def get(self, key: str, /) -> bytes | str | None: ...

    def delete(self, key: str, /) -> object: ...


class RedisReplayCache:
    """Replay cache shared across workers through a Redis-compatible client.

    Entries are remembered as a Redis key holding the recorded timestamp,
    expiring after the TTL given to ``remember`` — the same per-entry expiry
    semantics as :class:`~signedhook.replay.MemoryReplayCache`, but visible
    to every worker. ``seen_within`` and ``remember`` each run as a single
    atomic Redis command, so concurrent workers cannot corrupt state.

    Args:
        client: a connected Redis client (e.g. ``redis.Redis(...)``). The
            cache only calls ``set``/``get``/``delete`` on it; install the
            client with ``pip install signedhook[redis]`` or bring your own
            Redis-compatible library.
        namespace: key prefix, so unrelated applications can share one
            Redis database (default ``"signedhook:replay"``).
        clock: monotonic-time callable, injectable for tests.

    Example:
        >>> import redis  # doctest: +SKIP
        >>> cache = RedisReplayCache(redis.Redis(host="redis.internal"))  # doctest: +SKIP
        >>> verify_with_replay(payload, headers, cache, secrets=SECRET)  # doctest: +SKIP
    """

    def __init__(
        self,
        client: _RedisLike,
        *,
        namespace: str = "signedhook:replay",
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not namespace:
            raise ConfigurationError("namespace must be a non-empty string")
        self._client = client
        self._namespace = namespace
        self._clock = clock

    def _namespaced(self, key: str) -> str:
        return f"{self._namespace}:{key}"

    def seen_within(self, key: str, ttl_seconds: float) -> bool:
        """Return True when ``key`` was remembered less than ``ttl_seconds`` ago."""
        raw = self._client.get(self._namespaced(key))
        if raw is None:
            return False
        remembered_at = float(raw if isinstance(raw, str) else raw.decode("ascii"))
        return (self._clock() - remembered_at) < ttl_seconds

    def remember(self, key: str, ttl_seconds: float) -> None:
        """Record ``key`` with a Redis TTL of ``ceil(ttl_seconds)`` seconds."""
        if ttl_seconds <= 0:
            raise ConfigurationError("ttl_seconds must be positive")
        self._client.set(
            self._namespaced(key),
            repr(self._clock()),
            ex=max(1, math.ceil(ttl_seconds)),
            nx=False,
        )

    def discard(self, key: str) -> None:
        """Explicitly forget one key (e.g. after compensating actions)."""
        self._client.delete(self._namespaced(key))


class SQLiteReplayCache:
    """Replay cache shared across worker processes via a SQLite file.

    Every worker constructs its own instance on the same database path;
    SQLite's WAL journal mode plus a busy timeout serialise writers safely
    while readers never block. Uses only the standard library — no server,
    no extra dependency; ideal for single-host deployments (gunicorn/uvicorn
    workers on one machine). For multi-host deployments use
    :class:`RedisReplayCache`.

    Args:
        path: database file path; pass the SAME path in every worker.
            ``":memory:"`` creates a private in-memory database (single
            process / tests only — it cannot be shared).
        namespace: row namespace, so unrelated applications can share one
            database file (default ``"default"``).
        clock: wall-clock callable, injectable for tests.
        prune_after_seconds: horizon for lazy deletion of stale rows on
            write (default 7 days); entries are not kept forever.

    Example:
        >>> cache = SQLiteReplayCache("/var/lib/app/replay.sqlite3")  # doctest: +SKIP
        >>> verify_with_replay(payload, headers, cache, secrets=SECRET)  # doctest: +SKIP
    """

    def __init__(
        self,
        path: str | PathLike[str],
        *,
        namespace: str = "default",
        clock: Callable[[], float] = time.time,
        prune_after_seconds: float = 7 * 86_400,
    ) -> None:
        if not namespace:
            raise ConfigurationError("namespace must be a non-empty string")
        if prune_after_seconds <= 0:
            raise ConfigurationError("prune_after_seconds must be positive")
        self._namespace = namespace
        self._clock = clock
        self._prune_after = prune_after_seconds
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False, timeout=5.0)
        try:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS replay_cache ("
                "namespace TEXT NOT NULL, key TEXT NOT NULL, "
                "remembered_at REAL NOT NULL, "
                "PRIMARY KEY (namespace, key)) WITHOUT ROWID"
            )
            self._conn.commit()
        except BaseException:
            self._conn.close()
            raise

    def seen_within(self, key: str, ttl_seconds: float) -> bool:
        """Return True when ``key`` was remembered less than ``ttl_seconds`` ago."""
        with self._lock:
            cursor = self._conn.execute(
                "SELECT remembered_at FROM replay_cache WHERE namespace = ? AND key = ?",
                (self._namespace, key),
            )
            row = cursor.fetchone()
        if row is None:
            return False
        remembered_at = float(row[0])
        return (self._clock() - remembered_at) < ttl_seconds

    def remember(self, key: str, ttl_seconds: float) -> None:
        """Record ``key``, overwriting (and re-windowing) any earlier entry."""
        if ttl_seconds <= 0:
            raise ConfigurationError("ttl_seconds must be positive")
        now = self._clock()
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO replay_cache (namespace, key, remembered_at) "
                "VALUES (?, ?, ?)",
                (self._namespace, key, now),
            )
            self._conn.execute(
                "DELETE FROM replay_cache WHERE remembered_at < ?",
                (now - self._prune_after,),
            )
            self._conn.commit()

    def discard(self, key: str) -> None:
        """Explicitly forget one key (e.g. after compensating actions)."""
        with self._lock:
            self._conn.execute(
                "DELETE FROM replay_cache WHERE namespace = ? AND key = ?",
                (self._namespace, key),
            )
            self._conn.commit()

    def close(self) -> None:
        """Close the underlying connection (call once per worker on shutdown)."""
        with self._lock:
            self._conn.close()

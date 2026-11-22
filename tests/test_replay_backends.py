"""Shared replay-cache backend tests (Redis-compatible and SQLite)."""

from __future__ import annotations

import asyncio
import math
from pathlib import Path
from typing import Any

import pytest

from conftest import NOW, PAYLOAD, STD_SECRET_HEADER, std_headers
from signedhook import (
    AsyncMemoryReplayCache,
    ConfigurationError,
    MemoryReplayCache,
    RedisReplayCache,
    ReplayRejectedError,
    SQLiteReplayCache,
    verify_with_replay,
)


class FakeClock:
    """Mutable clock: tests advance time by assigning ``.now``."""

    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeRedis:
    """Minimal Redis-compatible client implementing the operations used.

    Simulates Redis server-side key expiry: ``set`` records the set time and
    the ``ex`` argument; ``get`` returns None for keys whose TTL elapsed.
    """

    def __init__(self, clock: FakeClock, returns_bytes: bool = True) -> None:
        self.clock = clock
        self.store: dict[str, tuple[float, str]] = {}  # key -> (set_at, value)
        self.expires: dict[str, int] = {}
        self.returns_bytes = returns_bytes
        self.last_set_kwargs: dict[str, Any] = {}

    def set(self, key: str, value: str, /, *, ex: int, nx: bool = False) -> bool:
        self.last_set_kwargs = {"ex": ex, "nx": nx}
        self.store[key] = (self.clock.now, value)
        self.expires[key] = ex
        return True

    def get(self, key: str, /) -> bytes | str | None:
        entry = self.store.get(key)
        if entry is None:
            return None
        set_at, value = entry
        if self.clock.now - set_at >= self.expires.get(key, 0):
            del self.store[key]
            self.expires.pop(key, None)
            return None
        return value.encode("ascii") if self.returns_bytes else value

    def delete(self, key: str, /) -> int:
        existed = key in self.store
        self.store.pop(key, None)
        self.expires.pop(key, None)
        return int(existed)


class TestRedisReplayCache:
    def test_remember_and_seen_within(self) -> None:
        clock = FakeClock()
        cache = RedisReplayCache(FakeRedis(clock), clock=clock)
        assert cache.seen_within("k", 900) is False
        cache.remember("k", 900)
        assert cache.seen_within("k", 900) is True

    def test_expiry_by_clock(self) -> None:
        clock = FakeClock()
        cache = RedisReplayCache(FakeRedis(clock), clock=clock)
        cache.remember("k", 900)
        clock.now += 901
        assert cache.seen_within("k", 900) is False

    def test_remember_extends_window(self) -> None:
        clock = FakeClock()
        cache = RedisReplayCache(FakeRedis(clock), clock=clock)
        cache.remember("k", 900)
        clock.now += 800
        cache.remember("k", 900)
        clock.now += 800
        assert cache.seen_within("k", 900) is True

    def test_ttl_shorter_than_call_window(self) -> None:
        clock = FakeClock()
        cache = RedisReplayCache(FakeRedis(clock), clock=clock)
        cache.remember("k", 100)
        clock.now += 150
        # remembered 150s ago: within a 900s call window, but the entry's
        # own 100s TTL has elapsed (the server expires the key), mirroring
        # MemoryReplayCache semantics.
        assert cache.seen_within("k", 900) is False

    def test_discard(self) -> None:
        clock = FakeClock()
        cache = RedisReplayCache(FakeRedis(clock), clock=clock)
        cache.remember("k", 900)
        cache.discard("k")
        assert cache.seen_within("k", 900) is False

    def test_namespaces_are_isolated(self) -> None:
        clock = FakeClock()
        client = FakeRedis(clock)
        one = RedisReplayCache(client, namespace="app-one", clock=clock)
        two = RedisReplayCache(client, namespace="app-two", clock=clock)
        one.remember("k", 900)
        assert two.seen_within("k", 900) is False
        assert one.seen_within("k", 900) is True

    def test_remember_sets_expiry_on_client(self) -> None:
        clock = FakeClock()
        client = FakeRedis(clock)
        cache = RedisReplayCache(client, clock=clock)
        cache.remember("k", 900.5)
        assert client.last_set_kwargs == {"ex": math.ceil(900.5), "nx": False}

    def test_string_returning_client(self) -> None:
        clock = FakeClock()
        cache = RedisReplayCache(FakeRedis(clock, returns_bytes=False), clock=clock)
        cache.remember("k", 900)
        assert cache.seen_within("k", 900) is True

    def test_non_positive_ttl_rejected(self) -> None:
        clock = FakeClock()
        cache = RedisReplayCache(FakeRedis(clock), clock=clock)
        with pytest.raises(ConfigurationError):
            cache.remember("k", 0)

    def test_empty_namespace_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            RedisReplayCache(FakeRedis(FakeClock()), namespace="")


class TestSQLiteReplayCache:
    def test_remember_and_seen_within(self, tmp_path: Path) -> None:
        cache = SQLiteReplayCache(tmp_path / "replay.db")
        assert cache.seen_within("k", 900) is False
        cache.remember("k", 900)
        assert cache.seen_within("k", 900) is True
        cache.close()

    def test_shared_across_worker_connections(self, tmp_path: Path) -> None:
        path = tmp_path / "replay.db"
        worker_one = SQLiteReplayCache(path)
        worker_two = SQLiteReplayCache(path)
        worker_one.remember("k", 900)
        assert worker_two.seen_within("k", 900) is True
        worker_two.discard("k")
        assert worker_one.seen_within("k", 900) is False
        worker_one.close()
        worker_two.close()

    def test_expiry_by_clock(self, tmp_path: Path) -> None:
        clock = FakeClock()
        cache = SQLiteReplayCache(tmp_path / "replay.db", clock=clock)
        cache.remember("k", 900)
        clock.now += 901
        assert cache.seen_within("k", 900) is False
        cache.close()

    def test_discard(self, tmp_path: Path) -> None:
        cache = SQLiteReplayCache(tmp_path / "replay.db")
        cache.remember("k", 900)
        cache.discard("k")
        assert cache.seen_within("k", 900) is False
        cache.close()

    def test_namespaces_are_isolated(self, tmp_path: Path) -> None:
        path = tmp_path / "replay.db"
        one = SQLiteReplayCache(path, namespace="one")
        two = SQLiteReplayCache(path, namespace="two")
        one.remember("k", 900)
        assert two.seen_within("k", 900) is False
        assert one.seen_within("k", 900) is True
        one.close()
        two.close()

    def test_prune_after_horizon(self, tmp_path: Path) -> None:
        clock = FakeClock()
        cache = SQLiteReplayCache(tmp_path / "replay.db", clock=clock, prune_after_seconds=60)
        cache.remember("old", 900)
        clock.now += 120
        cache.remember("new", 900)  # triggers pruning of rows older than 60s
        assert cache.seen_within("old", 900) is False
        assert cache.seen_within("new", 900) is True
        cache.close()

    def test_persistence_across_reopen(self, tmp_path: Path) -> None:
        path = tmp_path / "replay.db"
        cache = SQLiteReplayCache(path)
        cache.remember("k", 900)
        cache.close()
        reopened = SQLiteReplayCache(path)
        assert reopened.seen_within("k", 900) is True
        reopened.close()

    def test_non_positive_ttl_rejected(self, tmp_path: Path) -> None:
        cache = SQLiteReplayCache(tmp_path / "replay.db")
        with pytest.raises(ConfigurationError):
            cache.remember("k", -1)
        cache.close()

    def test_empty_namespace_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            SQLiteReplayCache(tmp_path / "replay.db", namespace="")

    def test_non_positive_prune_horizon_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigurationError):
            SQLiteReplayCache(tmp_path / "replay.db", prune_after_seconds=0)


class TestVerifyWithReplayIntegration:
    def test_redis_backend_rejects_replayed_standard_delivery(self) -> None:
        clock = FakeClock()
        cache = RedisReplayCache(FakeRedis(clock), clock=clock)
        result = verify_with_replay(
            PAYLOAD, std_headers(), cache, secrets=STD_SECRET_HEADER, now=NOW
        )
        assert result.provider == "standard"
        with pytest.raises(ReplayRejectedError):
            verify_with_replay(PAYLOAD, std_headers(), cache, secrets=STD_SECRET_HEADER, now=NOW)

    def test_sqlite_backend_rejects_replayed_standard_delivery(self, tmp_path: Path) -> None:
        cache = SQLiteReplayCache(tmp_path / "replay.db")
        verify_with_replay(PAYLOAD, std_headers(), cache, secrets=STD_SECRET_HEADER, now=NOW)
        with pytest.raises(ReplayRejectedError):
            verify_with_replay(PAYLOAD, std_headers(), cache, secrets=STD_SECRET_HEADER, now=NOW)
        cache.close()


class TestMemoryReplayCacheMaxsize:
    """Bounded in-memory caches evict the least recently remembered key."""

    def test_evicts_oldest_when_full(self) -> None:
        cache = MemoryReplayCache(maxsize=2)
        cache.remember("a", 60)
        cache.remember("b", 60)
        cache.remember("c", 60)
        assert len(cache) == 2
        assert cache.seen_within("a", 60) is False  # evicted
        assert cache.seen_within("b", 60) is True
        assert cache.seen_within("c", 60) is True

    def test_remember_refreshes_recency(self) -> None:
        cache = MemoryReplayCache(maxsize=2)
        cache.remember("a", 60)
        cache.remember("b", 60)
        cache.remember("a", 60)  # refresh: "a" is now the most recent
        cache.remember("c", 60)  # evicts "b", not "a"
        assert cache.seen_within("a", 60) is True
        assert cache.seen_within("b", 60) is False
        assert cache.seen_within("c", 60) is True

    def test_expired_entries_do_not_count_against_maxsize(self) -> None:
        cache = MemoryReplayCache(maxsize=2)
        cache.remember("a", 60)
        cache.remember("b", 0.0)  # expires immediately
        cache.remember("c", 60)
        assert len(cache) == 2
        assert cache.seen_within("a", 60) is True
        assert cache.seen_within("c", 60) is True

    def test_invalid_maxsize_rejected(self) -> None:
        for bad in (0, -1, True, "5"):  # type: ignore[arg-type]
            with pytest.raises(ConfigurationError):
                MemoryReplayCache(maxsize=bad)

    def test_none_maxsize_is_unbounded(self) -> None:
        cache = MemoryReplayCache()
        for i in range(50):
            cache.remember(f"key-{i}", 60)
        assert len(cache) == 50

    def test_async_memory_cache_maxsize(self) -> None:
        async def main() -> None:
            cache = AsyncMemoryReplayCache(maxsize=1)
            await cache.remember("a", 60)
            await cache.remember("b", 60)
            assert len(cache) == 1
            assert await cache.seen_within("a", 60) is False
            assert await cache.seen_within("b", 60) is True

        asyncio.run(main())

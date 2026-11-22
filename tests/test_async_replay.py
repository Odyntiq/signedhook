"""Async replay protection: protocol, backends and async entry points.

Async tests run through ``asyncio.run`` inside plain sync test functions so
the suite needs no async plugin. The async Redis backend is exercised with
an in-memory fake implementing the same command surface; the async SQLite
backend runs against real aiosqlite when installed.
"""

from __future__ import annotations

import asyncio
import math
from pathlib import Path
from typing import Any

import pytest

from conftest import (
    NOW,
    PAYLOAD,
    STD_SECRET_HEADER,
    TWILIO_PARAMS,
    TWILIO_SIG,
    TWILIO_TOKEN,
    TWILIO_URL,
    std_headers,
)
from signedhook import (
    AsyncMemoryReplayCache,
    AsyncRedisReplayCache,
    AsyncSQLiteReplayCache,
    ConfigurationError,
    MemoryReplayCache,
    ReplayRejectedError,
    SignatureMismatchError,
    sign_twilio,
    verify_twilio_async,
    verify_with_replay_async,
)


class FakeClock:
    def __init__(self, now: float = 1_000_000.0) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


class FakeAsyncRedis:
    """Async twin of the sync fake: same server-side TTL simulation."""

    def __init__(self, clock: FakeClock) -> None:
        self.clock = clock
        self.store: dict[str, tuple[float, str]] = {}
        self.expires: dict[str, int] = {}
        self.last_set_kwargs: dict[str, Any] = {}

    async def set(self, key: str, value: str, /, *, ex: int, nx: bool = False) -> bool:
        self.last_set_kwargs = {"ex": ex, "nx": nx}
        self.store[key] = (self.clock.now, value)
        self.expires[key] = ex
        return True

    async def get(self, key: str, /) -> bytes | None:
        entry = self.store.get(key)
        if entry is None:
            return None
        set_at, value = entry
        if self.clock.now - set_at >= self.expires.get(key, 0):
            del self.store[key]
            self.expires.pop(key, None)
            return None
        return value.encode("ascii")

    async def delete(self, key: str, /) -> int:
        existed = key in self.store
        self.store.pop(key, None)
        self.expires.pop(key, None)
        return int(existed)


class TestAsyncMemoryReplayCache:
    def test_remember_seen_discard(self) -> None:
        async def main() -> None:
            cache = AsyncMemoryReplayCache()
            assert await cache.seen_within("k", 900) is False
            await cache.remember("k", 900)
            assert await cache.seen_within("k", 900) is True
            await cache.discard("k")
            assert await cache.seen_within("k", 900) is False

        asyncio.run(main())

    def test_shares_state_with_sync_inner(self) -> None:
        async def main() -> None:
            inner = MemoryReplayCache()
            shared = AsyncMemoryReplayCache(inner)
            await shared.remember("k", 900)
            assert inner.seen_within("k", 900) is True

        asyncio.run(main())


class TestAsyncRedisReplayCache:
    def _cache(self, clock: FakeClock) -> AsyncRedisReplayCache:
        return AsyncRedisReplayCache(FakeAsyncRedis(clock), clock=clock)

    def test_remember_and_seen_within(self) -> None:
        async def main() -> None:
            clock = FakeClock()
            cache = self._cache(clock)
            assert await cache.seen_within("k", 900) is False
            await cache.remember("k", 900)
            assert await cache.seen_within("k", 900) is True

        asyncio.run(main())

    def test_expiry_by_clock(self) -> None:
        async def main() -> None:
            clock = FakeClock()
            cache = self._cache(clock)
            await cache.remember("k", 900)
            clock.now += 901
            assert await cache.seen_within("k", 900) is False

        asyncio.run(main())

    def test_ttl_ceil_passed_to_client(self) -> None:
        async def main() -> None:
            clock = FakeClock()
            fake = FakeAsyncRedis(clock)
            cache = AsyncRedisReplayCache(fake, clock=clock)
            await cache.remember("k", 900.5)
            assert fake.last_set_kwargs == {"ex": math.ceil(900.5), "nx": False}

        asyncio.run(main())

    def test_namespaces_are_isolated(self) -> None:
        async def main() -> None:
            clock = FakeClock()
            client = FakeAsyncRedis(clock)
            one = AsyncRedisReplayCache(client, namespace="one", clock=clock)
            two = AsyncRedisReplayCache(client, namespace="two", clock=clock)
            await one.remember("k", 900)
            assert await two.seen_within("k", 900) is False
            assert await one.seen_within("k", 900) is True

        asyncio.run(main())

    def test_discard(self) -> None:
        async def main() -> None:
            clock = FakeClock()
            cache = self._cache(clock)
            await cache.remember("k", 900)
            await cache.discard("k")
            assert await cache.seen_within("k", 900) is False

        asyncio.run(main())

    def test_empty_namespace_rejected(self) -> None:
        with pytest.raises(ConfigurationError):
            AsyncRedisReplayCache(FakeAsyncRedis(FakeClock()), namespace="")


class TestAsyncSQLiteReplayCache:
    def test_connect_remember_seen_close(self, tmp_path: Path) -> None:
        pytest.importorskip("aiosqlite")

        async def main() -> None:
            cache = await AsyncSQLiteReplayCache.connect(tmp_path / "replay.db")
            try:
                assert await cache.seen_within("k", 900) is False
                await cache.remember("k", 900)
                assert await cache.seen_within("k", 900) is True
            finally:
                await cache.close()

        asyncio.run(main())

    def test_shared_across_connections(self, tmp_path: Path) -> None:
        pytest.importorskip("aiosqlite")

        async def main() -> None:
            path = str(tmp_path / "replay.db")
            one = await AsyncSQLiteReplayCache.connect(path)
            two = await AsyncSQLiteReplayCache.connect(path)
            try:
                await one.remember("k", 900)
                assert await two.seen_within("k", 900) is True
                await two.discard("k")
                assert await one.seen_within("k", 900) is False
            finally:
                await one.close()
                await two.close()

        asyncio.run(main())

    def test_namespaces_are_isolated(self, tmp_path: Path) -> None:
        pytest.importorskip("aiosqlite")

        async def main() -> None:
            path = str(tmp_path / "replay.db")
            one = await AsyncSQLiteReplayCache.connect(path, namespace="one")
            two = await AsyncSQLiteReplayCache.connect(path, namespace="two")
            try:
                await one.remember("k", 900)
                assert await two.seen_within("k", 900) is False
            finally:
                await one.close()
                await two.close()

        asyncio.run(main())

    def test_persistence_across_reopen(self, tmp_path: Path) -> None:
        pytest.importorskip("aiosqlite")

        async def main() -> None:
            path = str(tmp_path / "replay.db")
            cache = await AsyncSQLiteReplayCache.connect(path)
            await cache.remember("k", 900)
            await cache.close()
            reopened = await AsyncSQLiteReplayCache.connect(path)
            try:
                assert await reopened.seen_within("k", 900) is True
            finally:
                await reopened.close()

        asyncio.run(main())

    def test_non_positive_ttl_rejected(self, tmp_path: Path) -> None:
        pytest.importorskip("aiosqlite")

        async def main() -> None:
            cache = await AsyncSQLiteReplayCache.connect(tmp_path / "replay.db")
            try:
                with pytest.raises(ConfigurationError):
                    await cache.remember("k", 0)
            finally:
                await cache.close()

        asyncio.run(main())

    def test_empty_namespace_rejected(self, tmp_path: Path) -> None:
        pytest.importorskip("aiosqlite")

        async def main() -> None:
            cache = await AsyncSQLiteReplayCache.connect(tmp_path / "replay.db")
            await cache.close()
            with pytest.raises(ConfigurationError):
                AsyncSQLiteReplayCache(
                    await _connect_raw(str(tmp_path / "replay.db")), namespace=""
                )

        async def _connect_raw(path: str) -> Any:
            import aiosqlite

            conn = await aiosqlite.connect(path)
            await conn.close()
            return conn

        asyncio.run(main())


class TestVerifyWithReplayAsync:
    def test_happy_path_and_replay_rejection(self) -> None:
        async def main() -> None:
            cache = AsyncMemoryReplayCache()
            result = await verify_with_replay_async(
                PAYLOAD, std_headers(), cache, secrets=STD_SECRET_HEADER, now=NOW
            )
            assert result.provider == "standard"
            with pytest.raises(ReplayRejectedError):
                await verify_with_replay_async(
                    PAYLOAD, std_headers(), cache, secrets=STD_SECRET_HEADER, now=NOW
                )

        asyncio.run(main())

    def test_redis_backend_rejects_replayed_delivery(self) -> None:
        async def main() -> None:
            clock = FakeClock()
            cache = AsyncRedisReplayCache(FakeAsyncRedis(clock), clock=clock)
            await verify_with_replay_async(
                PAYLOAD, std_headers(), cache, secrets=STD_SECRET_HEADER, now=NOW
            )
            with pytest.raises(ReplayRejectedError):
                await verify_with_replay_async(
                    PAYLOAD, std_headers(), cache, secrets=STD_SECRET_HEADER, now=NOW
                )

        asyncio.run(main())

    def test_unverified_payload_never_touches_cache(self) -> None:
        async def main() -> None:
            cache = AsyncMemoryReplayCache()
            with pytest.raises(SignatureMismatchError):
                await verify_with_replay_async(
                    PAYLOAD, std_headers(), cache, secrets="wrong", now=NOW
                )
            assert len(cache) == 0

        asyncio.run(main())

    def test_key_header_resolution(self) -> None:
        async def main() -> None:
            headers = {
                "x-hub-signature-256": "sha256=" + _gh_sig(PAYLOAD),
                "x-github-delivery": "delivery-7",
            }
            cache = AsyncMemoryReplayCache()
            result = await verify_with_replay_async(
                PAYLOAD,
                headers,
                cache,
                secrets="gh-secret",
                key_header="x-github-delivery",
                now=NOW,
            )
            assert result.provider == "github"
            assert await cache.seen_within("delivery-7", 900)

        asyncio.run(main())


def _gh_sig(payload: bytes) -> str:
    from conftest import hmac_sha256_hex

    return hmac_sha256_hex("gh-secret", payload)


class TestVerifyTwilioAsync:
    def test_happy_path_and_replay_rejection(self) -> None:
        async def main() -> None:
            headers = {"x-twilio-signature": TWILIO_SIG}
            cache = AsyncMemoryReplayCache()
            result = await verify_twilio_async(
                TWILIO_URL,
                TWILIO_PARAMS,
                headers,
                secrets=TWILIO_TOKEN,
                replay_cache=cache,
            )
            assert result.provider == "twilio"
            with pytest.raises(ReplayRejectedError):
                await verify_twilio_async(
                    TWILIO_URL,
                    TWILIO_PARAMS,
                    headers,
                    secrets=TWILIO_TOKEN,
                    replay_cache=cache,
                )

        asyncio.run(main())

    def test_without_cache_matches_sync_result(self) -> None:
        async def main() -> None:
            from signedhook import verify_twilio

            headers = sign_twilio(TWILIO_URL, TWILIO_PARAMS, secret=TWILIO_TOKEN)
            async_result = await verify_twilio_async(
                TWILIO_URL, TWILIO_PARAMS, headers, secrets=TWILIO_TOKEN
            )
            sync_result = verify_twilio(TWILIO_URL, TWILIO_PARAMS, headers, secrets=TWILIO_TOKEN)
            assert async_result == sync_result

        asyncio.run(main())

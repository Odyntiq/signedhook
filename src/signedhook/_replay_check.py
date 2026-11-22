"""Replay-cache plumbing shared by verify, streaming and the integrations.

Runtime duck-typing checks for cache objects (the caches are structural
:class:`typing.Protocol` classes, which cannot be used with ``isinstance``),
plus the resolve-check-remember sequence every replay-protected code path
runs after a signature matches. Keeping it in one place guarantees the
verify-first ordering and key-resolution order can never drift between
:func:`signedhook.verify_with_replay`, its async twin,
:class:`signedhook.StreamingVerifier` and the framework integrations.
"""

from __future__ import annotations

from collections.abc import Mapping
from inspect import iscoroutinefunction
from typing import TYPE_CHECKING, Any

from ._errors import ConfigurationError, ReplayRejectedError
from .replay import AsyncReplayCache, ReplayCache

if TYPE_CHECKING:  # pragma: no cover
    from ._types import VerificationResult

__all__ = [
    "apply_replay",
    "apply_replay_async",
    "is_async_replay_cache",
    "is_replay_cache",
    "resolve_replay_key",
]


def is_replay_cache(obj: Any) -> bool:
    """Return True when ``obj`` structurally implements the sync protocol."""
    if callable(obj):  # factories / classes are not cache instances
        return False
    return callable(getattr(obj, "seen_within", None)) and callable(getattr(obj, "remember", None))


def is_async_replay_cache(obj: Any) -> bool:
    """Return True when ``obj`` structurally implements the async protocol."""
    if callable(obj):  # factories / classes are not cache instances
        return False
    seen = getattr(obj, "seen_within", None)
    remember = getattr(obj, "remember", None)
    return (
        seen is not None
        and remember is not None
        and iscoroutinefunction(seen)
        and iscoroutinefunction(remember)
    )


def resolve_replay_key(
    key: str | None,
    key_header: str | None,
    headers: Mapping[str, str],
    result: VerificationResult,
) -> str:
    """Resolve the replay dedupe key: explicit key → header → message id."""
    key_id = key
    if key_id is None and key_header is not None:
        key_id = {str(name).lower(): value for name, value in headers.items()}.get(
            key_header.lower()
        )
    if key_id is None:
        key_id = result.message_key
    if not key_id:
        raise ConfigurationError(
            "no replay key available: pass key=, key_header=, or use a scheme that "
            "signs a message id (standard)"
        )
    return key_id


def apply_replay(
    cache: ReplayCache,
    result: VerificationResult,
    *,
    key: str | None = None,
    key_header: str | None = None,
    headers: Mapping[str, str],
    ttl_seconds: float = 900,
) -> None:
    """Check and consume the replay key for an already-verified result.

    Call only *after* the signature matched — never before — so
    unauthenticated traffic cannot poison the cache. Raises
    :class:`ReplayRejectedError` when the key was already accepted, and
    :class:`ConfigurationError` when no dedupe key can be resolved.
    """
    key_id = resolve_replay_key(key, key_header, headers, result)
    if cache.seen_within(key_id, ttl_seconds):
        raise ReplayRejectedError(key_id)
    cache.remember(key_id, ttl_seconds)


async def apply_replay_async(
    cache: AsyncReplayCache,
    result: VerificationResult,
    *,
    key: str | None = None,
    key_header: str | None = None,
    headers: Mapping[str, str],
    ttl_seconds: float = 900,
) -> None:
    """Awaitable twin of :func:`apply_replay` for async cache backends.

    Identical semantics and ordering; only the two cache operations are
    awaited, so the event loop is never blocked by the store.
    """
    key_id = resolve_replay_key(key, key_header, headers, result)
    if await cache.seen_within(key_id, ttl_seconds):
        raise ReplayRejectedError(key_id)
    await cache.remember(key_id, ttl_seconds)

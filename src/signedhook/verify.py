"""Top-level verification API.

``verify()`` is the single entry point for receiver-side webhook
verification. It normalises headers, guards payload size, resolves the
provider scheme (auto-detected or strict), decodes secrets, and delegates to
the shared HMAC pipeline.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Mapping, Sequence
from typing import Final

from ._encoding import normalize_secret_values
from ._errors import (
    PayloadTooLargeError,
    SignedhookError,
)
from ._providers import detect_provider, get_provider
from ._replay_check import apply_replay, apply_replay_async
from ._settings import Settings
from ._types import VerificationResult
from .replay import AsyncReplayCache, ReplayCache

__all__ = [
    "UNSET",
    "UnsetType",
    "verify",
    "verify_with_replay",
    "verify_with_replay_async",
]

logger = logging.getLogger("signedhook.verify")


class UnsetType:
    """Type of the :data:`UNSET` sentinel (do not instantiate)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNSET"


UNSET: Final[UnsetType] = UnsetType()


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {str(key).lower(): value for key, value in headers.items()}


def verify(
    payload: bytes,
    headers: Mapping[str, str],
    *,
    secrets: str | Sequence[str],
    provider: str | None = "auto",
    tolerance: int | None | UnsetType = UNSET,
    now: int | None = None,
    settings: Settings | None = None,
) -> VerificationResult:
    """Verify a signed webhook payload.

    Args:
        payload: the raw request body, exactly as received. Must be
            ``bytes`` — re-encoding a ``str`` invalidates signatures.
        headers: request headers; keys are matched case-insensitively.
        secrets: one signing secret or an ordered sequence (rotation: the
            first secret that verifies wins, its index is reported).
        provider: ``"auto"`` detects the scheme from headers; a registered
            name (``"standard"``, ``"stripe"``, ``"github"``,
            ``"github-legacy"``, ``"slack"``, ``"shopify"``, ``"razorpay"``
            or custom) forces strict mode. ``"twilio"`` routes to a stub
            that explains Twilio signs the URL + form parameters — use
            :func:`signedhook.twilio.verify_twilio` for Twilio requests.
        tolerance: override the tolerance window in seconds; ``None``
            disables the timestamp check; leave unset to use
            :attr:`Settings.tolerance_seconds` (applies only to schemes that
            sign a timestamp; millisecond timestamps are normalised to
            seconds first).
        now: current Unix time in seconds (injectable for tests).
        settings: limits for this call; defaults to ``Settings()``.

    Returns:
        VerificationResult with the matched provider, timestamp (Unix
        seconds), secret rotation index and provider message key.

    Raises:
        TypeError: payload is not ``bytes``.
        PayloadTooLargeError: payload exceeds ``settings.max_payload_bytes``.
        UnknownProviderError: no scheme detected, ambiguous headers, or an
            unknown strict provider name.
        MissingHeaderError / InvalidHeaderFormatError: scheme headers absent
            or unparseable.
        TimestampToleranceExceededError: signed timestamp outside the window.
        SignatureMismatchError: no secret produced a matching signature.
        ConfigurationError: invalid secrets or settings.
    """
    settings = settings if settings is not None else Settings()
    if not isinstance(payload, bytes):
        raise TypeError(
            "payload must be raw bytes as received, not str — re-encoding invalidates signatures"
        )
    if len(payload) > settings.max_payload_bytes:
        raise PayloadTooLargeError(len(payload), settings.max_payload_bytes)

    lowered = _normalize_headers(headers)
    secret_values = normalize_secret_values(secrets)

    if provider is None or provider == "auto":
        scheme = detect_provider(lowered)
    else:
        scheme = get_provider(provider)

    if isinstance(tolerance, UnsetType):
        effective_tolerance = settings.tolerance_seconds
    else:
        effective_tolerance = tolerance

    current_time = int(time.time()) if now is None else now
    keys = tuple(scheme.secret_key(value) for value in secret_values)

    try:
        result = scheme.verify(
            payload, lowered, keys, now=current_time, tolerance=effective_tolerance
        )
    except SignedhookError as error:
        logger.debug(
            "webhook verification failed",
            extra={
                "provider": scheme.name,
                "outcome": "failure",
                "reason_code": error.code,
            },
        )
        raise
    logger.debug(
        "webhook verified",
        extra={
            "provider": result.provider,
            "outcome": "success",
            "reason_code": "",
            "matched_secret_index": result.matched_secret_index,
        },
    )
    return result


def verify_with_replay(
    payload: bytes,
    headers: Mapping[str, str],
    cache: ReplayCache,
    *,
    secrets: str | Sequence[str],
    provider: str | None = "auto",
    tolerance: int | None | UnsetType = UNSET,
    now: int | None = None,
    settings: Settings | None = None,
    key: str | None = None,
    key_header: str | None = None,
    ttl_seconds: float = 900,
) -> VerificationResult:
    """Verify a webhook and reject messages already accepted within ``ttl_seconds``.

    Signature verification runs FIRST; only successfully verified messages
    consume cache entries, so unauthenticated traffic cannot poison the
    cache. The dedupe key resolves in this order: explicit ``key``, the
    ``key_header`` header value (e.g. ``"x-github-delivery"``), then the
    scheme's own message id (Standard Webhooks ``webhook-id``).

    Args:
        cache: any object implementing the :class:`ReplayCache` protocol
            (:class:`MemoryReplayCache` is bundled; Redis-backed caches work
            too).
        ttl_seconds: replay window for the cache entries.

    See :func:`verify` for all other parameters and raised errors; raises
    :class:`ReplayRejectedError` when the key was already accepted, and
    :class:`ConfigurationError` when no dedupe key can be resolved.
    """
    result = verify(
        payload,
        headers,
        secrets=secrets,
        provider=provider,
        tolerance=tolerance,
        now=now,
        settings=settings,
    )
    apply_replay(
        cache, result, key=key, key_header=key_header, headers=headers, ttl_seconds=ttl_seconds
    )
    return result


async def verify_with_replay_async(
    payload: bytes,
    headers: Mapping[str, str],
    cache: AsyncReplayCache,
    *,
    secrets: str | Sequence[str],
    provider: str | None = "auto",
    tolerance: int | None | UnsetType = UNSET,
    now: int | None = None,
    settings: Settings | None = None,
    key: str | None = None,
    key_header: str | None = None,
    ttl_seconds: float = 900,
    offload: bool = False,
) -> VerificationResult:
    """Awaitable :func:`verify_with_replay` for asyncio applications.

    Signature verification runs synchronously (it is pure CPU work over an
    already-buffered body); only the two cache operations are awaited, so
    async stores such as :class:`~signedhook.replay_backends.
    AsyncRedisReplayCache` integrate without blocking the event loop. The
    verify-first ordering is preserved: unauthenticated traffic never
    touches the cache.

    Args:
        cache: any object implementing the :class:`AsyncReplayCache`
            protocol (``await seen_within(...)`` / ``await remember(...)``).
        offload: run the signature verification in a worker thread via
            :func:`asyncio.to_thread`. The HMAC over a typical webhook costs
            microseconds inline and offloading adds a thread hop, so the
            default is ``False``; pass ``True`` for deployments that accept
            very large bodies (tens of megabytes and up, via a raised
            ``max_payload_bytes``) where the inline digest would block the
            event loop for tens of milliseconds.

    See :func:`verify_with_replay` for all other parameters and raised
    errors; the two calls are behaviourally identical.
    """
    if offload:
        result = await asyncio.to_thread(
            verify,
            payload,
            headers,
            secrets=secrets,
            provider=provider,
            tolerance=tolerance,
            now=now,
            settings=settings,
        )
    else:
        result = verify(
            payload,
            headers,
            secrets=secrets,
            provider=provider,
            tolerance=tolerance,
            now=now,
            settings=settings,
        )
    await apply_replay_async(
        cache, result, key=key, key_header=key_header, headers=headers, ttl_seconds=ttl_seconds
    )
    return result

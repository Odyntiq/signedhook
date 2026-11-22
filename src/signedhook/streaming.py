"""Incremental verification for very large webhook bodies.

``verify()`` needs the whole payload in memory before doing anything. For
multi-hundred-megabyte deliveries that is wasteful and an amplification
vector: an attacker streams a huge body and the receiver buffers all of it
before noticing anything is wrong. Every built-in body-signing scheme,
however, computes its HMAC over ``prefix + payload + suffix`` where the
prefix and suffix are derived purely from *headers* (a timestamp, a message
id) — so the MAC state can be initialised from the headers alone, updated
chunk by chunk as the body arrives, and finalised the moment the body ends.

:class:`StreamingVerifier` does exactly that, with the size limit enforced
*during* feeding (oversized deliveries are aborted mid-stream instead of
after full buffering) and the constant-time comparison done once at the
end. Semantics are identical to :func:`signedhook.verify`: the same header
parsing, tolerance window, secret rotation and result object — equivalence
is pinned by tests that compare both paths for every built-in scheme.

    from signedhook import StreamingVerifier

    verifier = StreamingVerifier(headers, secrets=SECRET, provider="stripe")
    async for chunk in request.stream():
        verifier.feed(chunk)          # raises PayloadTooLargeError mid-stream
    result = verifier.finish()

Providers whose signed content cannot be decomposed this way (Twilio signs
the request URL and form parameters) are rejected with a precise
:class:`ConfigurationError`.
"""

from __future__ import annotations

import hmac
import logging
import time
from collections.abc import Iterable, Mapping, Sequence

from ._encoding import (
    normalize_secret_values,
    timestamp_to_seconds,
)
from ._errors import (
    ConfigurationError,
    PayloadTooLargeError,
    ReplayRejectedError,
    SignatureMismatchError,
    TimestampToleranceExceededError,
)
from ._providers import detect_provider, get_provider
from ._providers.base import ParsedSignature, Provider
from ._settings import Settings
from ._types import VerificationResult
from .replay import ReplayCache
from .verify import UNSET, UnsetType

__all__ = ["StreamingVerifier", "verify_stream"]

logger = logging.getLogger("signedhook.verify")


class StreamingVerifier:
    """Verify a body-signed webhook while the body is still arriving.

    Construction performs every step that only needs headers: provider
    resolution, signature parsing, the tolerance check and decomposition of
    the signed content into ``(prefix, suffix)``. The per-secret HMAC states
    are initialised with the prefix immediately, so an unauthenticated
    request fails fast — before a single body byte is fed.

    Args:
        headers: request headers; keys are matched case-insensitively.
        secrets: one signing secret or an ordered sequence (rotation: the
            first secret that verifies wins, its index is reported).
        provider: ``"auto"`` detects the scheme from headers; a registered
            name forces strict mode. ``"twilio"`` fails with a precise error.
        tolerance: override the tolerance window in seconds; ``None``
            disables the timestamp check; leave unset to use
            ``Settings.tolerance_seconds``.
        now: current Unix time in seconds (injectable for tests).
        settings: limits for this verification; defaults to ``Settings()``.
            ``max_payload_bytes`` is enforced incrementally in :meth:`feed`.
        replay_cache: optional :class:`~signedhook.replay.ReplayCache`;
            consulted by :meth:`finish` after the signature matches, so only
            verified messages consume entries.
        key: explicit replay dedupe key; overrides ``key_header`` and the
            scheme's own message id.
        key_header: header whose value is used as the replay key when
            ``key`` is not given (e.g. ``"x-github-delivery"``).
        ttl_seconds: replay window for the cache entries.

    Example:
        >>> verifier = StreamingVerifier(headers, secrets=SECRET)  # doctest: +SKIP
        >>> for chunk in body_chunks:  # doctest: +SKIP
        ...     verifier.feed(chunk)
        >>> result = verifier.finish()  # doctest: +SKIP
    """

    def __init__(
        self,
        headers: Mapping[str, str],
        *,
        secrets: str | Sequence[str],
        provider: str | None = "auto",
        tolerance: int | None | UnsetType = UNSET,
        now: int | None = None,
        settings: Settings | None = None,
        replay_cache: ReplayCache | None = None,
        key: str | None = None,
        key_header: str | None = None,
        ttl_seconds: float = 900,
    ) -> None:
        settings = settings if settings is not None else Settings()
        lowered = {str(name).lower(): value for name, value in headers.items()}
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
        parsed = scheme.parse_signature(lowered)
        if parsed.timestamp is not None and effective_tolerance is not None:
            delta = abs(
                current_time - timestamp_to_seconds(parsed.timestamp, scheme.timestamp_unit)
            )
            if delta > effective_tolerance:
                self._log_failure(scheme.name, TimestampToleranceExceededError.code)
                raise TimestampToleranceExceededError(delta, effective_tolerance)

        prefix, suffix = scheme.streaming_parts(lowered, parsed)

        self._scheme: Provider = scheme
        self._parsed: ParsedSignature = parsed
        self._headers: dict[str, str] = lowered
        self._suffix: bytes = suffix
        self._macs: list[hmac.HMAC] = [hmac.new(key, prefix, scheme.digest) for key in keys]
        self._size: int = 0
        self._limit: int = settings.max_payload_bytes
        self._finished: bool = False
        self._replay_cache: ReplayCache | None = replay_cache
        self._key: str | None = key
        self._key_header: str | None = key_header
        self._ttl_seconds: float = ttl_seconds

    def feed(self, chunk: bytes | bytearray | memoryview) -> None:
        """Absorb one body chunk into every secret's HMAC state.

        Raises:
            TypeError: ``chunk`` is not a bytes-like object (``str`` is
                rejected: re-encoding invalidates signatures).
            PayloadTooLargeError: the cumulative body size just exceeded
                ``settings.max_payload_bytes`` — stop reading the request.
            ConfigurationError: called after :meth:`finish`.
        """
        if self._finished:
            raise ConfigurationError("this StreamingVerifier was already finished")
        if isinstance(chunk, str):
            raise TypeError(
                "chunks must be raw bytes as received, not str — re-encoding invalidates signatures"
            )
        if not isinstance(chunk, (bytes, bytearray, memoryview)):
            raise TypeError("chunks must be bytes-like (bytes, bytearray or memoryview)")
        data = bytes(chunk)
        new_size = self._size + len(data)
        if new_size > self._limit:
            self._log_failure(self._scheme.name, PayloadTooLargeError.code)
            raise PayloadTooLargeError(new_size, self._limit)
        self._size = new_size
        for mac in self._macs:
            mac.update(data)

    def finish(self) -> VerificationResult:
        """Finalise the HMAC states and compare against the parsed signatures.

        Returns the same :class:`~signedhook.VerificationResult` an
        equivalent :func:`~signedhook.verify` call would return; calling
        ``finish()`` without ever feeding yields a zero-byte payload
        verification (valid for providers that sign empty bodies).

        Raises:
            SignatureMismatchError: no secret produced a matching signature.
            ReplayRejectedError: the dedupe key was already accepted.
            ConfigurationError: called twice, or the replay key cannot be
                resolved.
        """
        if self._finished:
            raise ConfigurationError("this StreamingVerifier was already finished")
        self._finished = True

        for mac in self._macs:
            mac.update(self._suffix)

        scheme = self._scheme
        parsed = self._parsed
        for position, mac in enumerate(self._macs):
            expected = mac.digest()
            for provided in parsed.signatures:
                if hmac.compare_digest(expected, provided):
                    result = VerificationResult(
                        provider=scheme.name,
                        scheme=scheme.scheme,
                        timestamp=(
                            timestamp_to_seconds(parsed.timestamp, scheme.timestamp_unit)
                            if parsed.timestamp is not None
                            else None
                        ),
                        matched_secret_index=position,
                        message_key=parsed.message_key,
                        payload_size=self._size,
                    )
                    self._apply_replay(result)
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
        self._log_failure(scheme.name, SignatureMismatchError.code)
        raise SignatureMismatchError(scheme.name)

    @property
    def payload_size(self) -> int:
        """Body bytes fed so far."""
        return self._size

    def _apply_replay(self, result: VerificationResult) -> None:
        cache = self._replay_cache
        if cache is None:
            return
        key_id = self._key
        if key_id is None and self._key_header is not None:
            key_id = self._headers.get(self._key_header.lower())
        if key_id is None:
            key_id = result.message_key
        if not key_id:
            raise ConfigurationError(
                "no replay key available: pass key=, key_header=, or use a scheme that "
                "signs a message id (standard)"
            )
        if cache.seen_within(key_id, self._ttl_seconds):
            self._log_failure(result.provider, ReplayRejectedError.code)
            raise ReplayRejectedError(key_id)
        cache.remember(key_id, self._ttl_seconds)

    @staticmethod
    def _log_failure(provider: str, reason_code: str) -> None:
        logger.debug(
            "webhook verification failed",
            extra={"provider": provider, "outcome": "failure", "reason_code": reason_code},
        )


def verify_stream(
    chunks: bytes | bytearray | memoryview | Iterable[bytes | bytearray | memoryview],
    headers: Mapping[str, str],
    *,
    secrets: str | Sequence[str],
    provider: str | None = "auto",
    tolerance: int | None | UnsetType = UNSET,
    now: int | None = None,
    settings: Settings | None = None,
    replay_cache: ReplayCache | None = None,
    key: str | None = None,
    key_header: str | None = None,
    ttl_seconds: float = 900,
) -> VerificationResult:
    """Verify a webhook from body chunks (or a whole body) incrementally.

    A convenience wrapper around :class:`StreamingVerifier` for callers with
    an iterable of chunks. Passing ``bytes``/``bytearray``/``memoryview``
    feeds it as a single chunk, which makes this a drop-in streaming-shaped
    alternative to :func:`~signedhook.verify`::

        result = verify_stream(request.body, headers, secrets=SECRET)

    See :class:`StreamingVerifier` for parameters and raised errors.
    """
    verifier = StreamingVerifier(
        headers,
        secrets=secrets,
        provider=provider,
        tolerance=tolerance,
        now=now,
        settings=settings,
        replay_cache=replay_cache,
        key=key,
        key_header=key_header,
        ttl_seconds=ttl_seconds,
    )
    if isinstance(chunks, (bytes, bytearray, memoryview)):
        verifier.feed(chunks)
    else:
        for chunk in chunks:
            verifier.feed(chunk)
    return verifier.finish()

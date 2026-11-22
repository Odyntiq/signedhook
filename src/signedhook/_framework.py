"""Shared machinery for the framework integrations (FastAPI, Flask, Django).

Streaming mode adds three pieces every integration needs: priming a
:class:`~signedhook.streaming.StreamingVerifier` from headers alone,
feeding it from the framework's request stream chunk by chunk, and a
capped buffered read for schemes that cannot stream. Keeping them here
guarantees the FastAPI, Flask and Django integrations behave identically —
the same fallback rule, the same mid-stream size enforcement, the same
chunk boundaries.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, Callable, Mapping, Sequence

from ._errors import ConfigurationError, PayloadTooLargeError
from ._settings import Settings
from .streaming import StreamingVerifier
from .verify import UnsetType

__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "feed_stream",
    "read_capped",
    "read_capped_async",
    "streaming_verifier_or_none",
]

#: Default body-read granularity for the WSGI streaming paths.
DEFAULT_CHUNK_SIZE = 64 * 1024


def streaming_verifier_or_none(
    headers: Mapping[str, str],
    *,
    secrets: str | Sequence[str],
    provider: str | None,
    tolerance: int | None | UnsetType,
    now: int | None,
    settings: Settings | None,
) -> StreamingVerifier | None:
    """Prime a :class:`StreamingVerifier`, or return ``None`` to buffer.

    Construction performs every step that only needs headers: provider
    resolution, signature parsing, the tolerance check and HMAC priming.
    When it succeeds the caller can feed the request stream straight into
    the verifier and reject bad deliveries without reading the body.

    A :class:`ConfigurationError` at construction means the resolved scheme
    cannot decompose its signed content around the body — Twilio signs the
    request URL plus sorted form parameters, and a custom provider may not
    implement ``streaming_parts`` — so ``None`` is returned and the caller
    falls back to buffered verification. Any other error (missing headers,
    stale timestamp, unparseable signature) propagates: it would fail
    identically in buffered mode, and failing before a single body byte is
    read is exactly the point.
    """
    try:
        return StreamingVerifier(
            headers,
            secrets=secrets,
            provider=provider,
            tolerance=tolerance,
            now=now,
            settings=settings,
        )
    except ConfigurationError:
        return None


def feed_stream(
    verifier: StreamingVerifier,
    read: Callable[[int], bytes],
    chunk_size: int,
) -> bytes:
    """Feed a request stream into ``verifier`` chunk by chunk until EOF.

    ``read`` is a callable returning the next ``chunk_size`` body bytes
    (``request.stream.read`` for Flask, ``request.read`` for Django).
    Returns the buffered body — the view still needs it — while the size
    limit is enforced by :meth:`StreamingVerifier.feed` mid-stream.
    """
    chunks: list[bytes] = []
    while True:
        chunk = read(chunk_size)
        if not chunk:
            break
        verifier.feed(chunk)
        chunks.append(chunk)
    return b"".join(chunks)


def read_capped(read: Callable[[int], bytes], chunk_size: int, limit: int) -> bytes:
    """Read a body to EOF enforcing ``limit`` mid-stream (buffered fallback).

    Used for schemes that cannot stream their HMAC (Twilio): the size limit
    still aborts the read before the rest of an oversized body arrives.
    """
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = read(chunk_size)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise PayloadTooLargeError(size, limit)
        chunks.append(chunk)
    return b"".join(chunks)


async def read_capped_async(stream: AsyncIterable[bytes], limit: int) -> bytes:
    """Async twin of :func:`read_capped` over a chunk iterable (ASGI)."""
    chunks: list[bytes] = []
    size = 0
    async for chunk in stream:
        size += len(chunk)
        if size > limit:
            raise PayloadTooLargeError(size, limit)
        chunks.append(chunk)
    return b"".join(chunks)

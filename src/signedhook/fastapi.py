"""Optional FastAPI integration.

Install with ``pip install signedhook[fastapi]``. The factory returns a
FastAPI dependency that reads the raw request body, verifies it with
signedhook, and converts failures into structured HTTP errors with
machine-readable ``code`` fields.

With ``stream=True`` the dependency consumes ``request.stream()`` — the
ASGI receive channel — chunk by chunk: the HMAC state is primed from the
headers alone (stale timestamps are rejected before a single body byte is
read), updated per chunk, and the payload-size limit aborts mid-stream.
The body is re-injected afterwards, so path-operation body parsing
(``event: dict`` etc.) works unchanged.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any, cast

from ._errors import SignedhookError
from ._framework import read_capped_async, streaming_verifier_or_none
from ._http import resolve_status
from ._replay_check import apply_replay, apply_replay_async, is_async_replay_cache
from ._settings import Settings
from ._types import VerificationResult
from .replay import AsyncReplayCache, ReplayCache
from .verify import UNSET, UnsetType, verify, verify_with_replay, verify_with_replay_async

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

try:
    from fastapi import HTTPException, Request  # noqa: TC004
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "signedhook.fastapi requires fastapi — install with: pip install signedhook[fastapi]"
    ) from exc

__all__ = ["webhook_dependency"]


def webhook_dependency(
    *,
    provider: str | None = "auto",
    secrets: str | list[str],
    tolerance: int | None | UnsetType = UNSET,
    now: int | None = None,
    settings: Settings | None = None,
    replay_cache: ReplayCache | AsyncReplayCache | None = None,
    key: str | None = None,
    key_header: str | None = None,
    ttl_seconds: float = 900,
    status_overrides: dict[type[SignedhookError], int] | None = None,
    stream: bool = False,
    offload: bool = False,
) -> Any:
    """Build a FastAPI dependency that verifies webhook requests.

    Example:
        verify_webhook = webhook_dependency(provider="stripe", secrets=STRIPE_SECRET)

        @app.post("/webhooks/stripe")
        async def stripe_events(
            event: dict, result: VerificationResult = Depends(verify_webhook)
        ):
            ...

    Failures raise :class:`fastapi.HTTPException` whose ``detail`` is
    ``{"code": <stable code>, "message": <sanitised message>}`` with the
    status resolved from the shared default map (413 too large, 400
    malformed, 401 unauthenticated, 409 replayed, 500 misconfiguration).
    ``status_overrides`` maps exact error classes to custom statuses.

    ``replay_cache`` accepts a sync :class:`~signedhook.replay.ReplayCache`
    or an async :class:`~signedhook.replay.AsyncReplayCache`; async caches
    are awaited, so ``redis.asyncio``-backed stores never block the event
    loop.

    Args:
        stream: verify incrementally from the ASGI request stream instead
            of buffering the body first. Stale timestamps fail before any
            body byte is read; the payload-size limit aborts mid-stream.
            Schemes that cannot stream (Twilio) transparently fall back to
            a size-capped buffered read. The body is re-injected, so
            path-operation body parsing works unchanged; do not also read
            ``request.stream()`` in the handler itself.
        offload: run buffered signature verification in a worker thread via
            :func:`asyncio.to_thread` — for deployments accepting very large
            bodies. Irrelevant with ``stream=True``, where the HMAC work is
            already spread across chunks.
    """
    overrides = status_overrides or {}

    async def dependency(request: Request) -> VerificationResult:
        headers = {name.lower(): value for name, value in request.headers.items()}
        try:
            if stream:
                verifier = streaming_verifier_or_none(
                    headers,
                    secrets=secrets,
                    provider=provider,
                    tolerance=tolerance,
                    now=now,
                    settings=settings,
                )
                if verifier is not None:
                    chunks: list[bytes] = []
                    async for chunk in request.stream():
                        verifier.feed(chunk)
                        chunks.append(chunk)
                    result = verifier.finish()
                    if replay_cache is not None:
                        if is_async_replay_cache(replay_cache):
                            await apply_replay_async(
                                cast(AsyncReplayCache, replay_cache),
                                result,
                                key=key,
                                key_header=key_header,
                                headers=headers,
                                ttl_seconds=ttl_seconds,
                            )
                        else:
                            apply_replay(
                                cast(ReplayCache, replay_cache),
                                result,
                                key=key,
                                key_header=key_header,
                                headers=headers,
                                ttl_seconds=ttl_seconds,
                            )
                    # Re-inject the body so downstream body parsing works.
                    request._body = b"".join(chunks)
                    return result
                # Non-streamable scheme (e.g. Twilio): capped buffered read.
                limit = (settings if settings is not None else Settings()).max_payload_bytes
                payload = await read_capped_async(request.stream(), limit)
                request._body = payload
            else:
                payload = await request.body()

            if replay_cache is not None and is_async_replay_cache(replay_cache):
                return await verify_with_replay_async(
                    payload,
                    headers,
                    cast(AsyncReplayCache, replay_cache),
                    secrets=secrets,
                    provider=provider,
                    tolerance=tolerance,
                    now=now,
                    settings=settings,
                    key=key,
                    key_header=key_header,
                    ttl_seconds=ttl_seconds,
                    offload=offload,
                )
            if replay_cache is not None:
                return verify_with_replay(
                    payload,
                    headers,
                    cast(ReplayCache, replay_cache),
                    secrets=secrets,
                    provider=provider,
                    tolerance=tolerance,
                    now=now,
                    settings=settings,
                    key=key,
                    key_header=key_header,
                    ttl_seconds=ttl_seconds,
                )
            if offload:
                return await asyncio.to_thread(
                    verify,
                    payload,
                    headers,
                    secrets=secrets,
                    provider=provider,
                    tolerance=tolerance,
                    now=now,
                    settings=settings,
                )
            return verify(
                payload,
                headers,
                secrets=secrets,
                provider=provider,
                tolerance=tolerance,
                now=now,
                settings=settings,
            )
        except SignedhookError as error:
            raise HTTPException(
                status_code=resolve_status(error, overrides),
                detail={"code": error.code, "message": str(error)},
            ) from error

    return dependency

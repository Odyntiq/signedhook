"""Optional FastAPI integration.

Install with ``pip install signedhook[fastapi]``. The factory returns a
FastAPI dependency that reads the raw request body, verifies it with
signedhook, and converts failures into structured HTTP errors with
machine-readable ``code`` fields.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from ._errors import SignedhookError
from ._http import resolve_status
from ._replay_check import is_async_replay_cache
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
    """
    overrides = status_overrides or {}

    async def dependency(request: Request) -> VerificationResult:
        payload = await request.body()
        headers = {name.lower(): value for name, value in request.headers.items()}
        try:
            if replay_cache is not None and is_async_replay_cache(replay_cache):
                async_cache = cast(AsyncReplayCache, replay_cache)
                return await verify_with_replay_async(
                    payload,
                    headers,
                    async_cache,
                    secrets=secrets,
                    provider=provider,
                    tolerance=tolerance,
                    now=now,
                    settings=settings,
                    key=key,
                    key_header=key_header,
                    ttl_seconds=ttl_seconds,
                )
            if replay_cache is not None:
                sync_cache = cast(ReplayCache, replay_cache)
                return verify_with_replay(
                    payload,
                    headers,
                    sync_cache,
                    secrets=secrets,
                    provider=provider,
                    tolerance=tolerance,
                    now=now,
                    settings=settings,
                    key=key,
                    key_header=key_header,
                    ttl_seconds=ttl_seconds,
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

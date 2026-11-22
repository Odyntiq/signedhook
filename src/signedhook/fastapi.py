"""Optional FastAPI integration.

Install with ``pip install signedhook[fastapi]``. The factory returns a
FastAPI dependency that reads the raw request body, verifies it with
signedhook, and converts failures into structured HTTP errors with
machine-readable ``code`` fields.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ._errors import (
    ConfigurationError,
    InvalidHeaderFormatError,
    MissingHeaderError,
    PayloadTooLargeError,
    ReplayRejectedError,
    SignatureMismatchError,
    SignedhookError,
    TimestampToleranceExceededError,
    UnknownProviderError,
)
from ._settings import Settings
from ._types import VerificationResult
from .replay import ReplayCache
from .verify import UNSET, UnsetType, verify, verify_with_replay

if TYPE_CHECKING:  # pragma: no cover
    from fastapi import Request

try:
    from fastapi import HTTPException, Request  # noqa: TC004
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "signedhook.fastapi requires fastapi — install with: pip install signedhook[fastapi]"
    ) from exc

__all__ = ["webhook_dependency"]

#: Ordered (error type, HTTP status) defaults, evaluated top to bottom.
_DEFAULT_STATUS_MAP: tuple[tuple[type[SignedhookError], int], ...] = (
    (PayloadTooLargeError, 413),
    (MissingHeaderError, 400),
    (InvalidHeaderFormatError, 400),
    (ReplayRejectedError, 409),
    (SignatureMismatchError, 401),
    (TimestampToleranceExceededError, 401),
    (UnknownProviderError, 401),
    (ConfigurationError, 500),
)


def webhook_dependency(
    *,
    provider: str | None = "auto",
    secrets: str | list[str],
    tolerance: int | None | UnsetType = UNSET,
    now: int | None = None,
    settings: Settings | None = None,
    replay_cache: ReplayCache | None = None,
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
    status resolved from :data:`_DEFAULT_STATUS_MAP` (413 too large, 400
    malformed, 401 unauthenticated, 409 replayed, 500 misconfiguration).
    ``status_overrides`` maps exact error classes to custom statuses.
    """
    overrides = status_overrides or {}

    def resolve_status(error: SignedhookError) -> int:
        error_type = type(error)
        if error_type in overrides:
            return overrides[error_type]
        for candidate, status in _DEFAULT_STATUS_MAP:
            if isinstance(error, candidate):
                return status
        return 500

    async def dependency(request: Request) -> VerificationResult:
        payload = await request.body()
        headers = {name.lower(): value for name, value in request.headers.items()}
        try:
            if replay_cache is not None:
                return verify_with_replay(
                    payload,
                    headers,
                    replay_cache,
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
                status_code=resolve_status(error),
                detail={"code": error.code, "message": str(error)},
            ) from error

    return dependency

"""Optional Flask integration.

Install with ``pip install signedhook[flask]``. The decorator reads the raw
request body (cached, so the view can re-read it), verifies it with
signedhook, injects the :class:`~signedhook.VerificationResult` into the
view and converts failures into structured JSON responses with
machine-readable ``code`` fields and the same status semantics as the
FastAPI integration (413 too large, 400 malformed, 401 unauthenticated,
409 replayed, 500 misconfiguration).
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from ._errors import SignedhookError
from ._http import resolve_status
from ._settings import Settings
from .replay import ReplayCache
from .verify import UNSET, UnsetType, verify, verify_with_replay

try:
    from flask import jsonify, request
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "signedhook.flask requires flask — install with: pip install signedhook[flask]"
    ) from exc

__all__ = ["verify_webhook"]


def verify_webhook(
    *,
    secrets: str | list[str],
    provider: str | None = "auto",
    tolerance: int | None | UnsetType = UNSET,
    now: int | None = None,
    settings: Settings | None = None,
    replay_cache: ReplayCache | None = None,
    key: str | None = None,
    key_header: str | None = None,
    ttl_seconds: float = 900,
    result_kwarg: str = "result",
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Build a view decorator that verifies webhook requests.

    Example:
        @app.post("/webhooks/stripe")
        @verify_webhook(provider="stripe", secrets=STRIPE_SECRET)
        def stripe_events(result: VerificationResult) -> dict:
            return {"verified_provider": result.provider}

    The body is read once via ``request.get_data()`` (Flask caches it, so
    the view can call ``request.get_data()`` again) and verified as raw
    bytes. On success the :class:`~signedhook.VerificationResult` is passed
    to the view as the ``result_kwarg`` keyword argument; declare it in the
    view signature. On failure the client receives
    ``{"detail": {"code": <stable code>, "message": <sanitised message>}}``
    with the mapped status.

    Args:
        result_kwarg: name of the view keyword argument that receives the
            verification result (default ``"result"``).

    See :func:`signedhook.verify` / :func:`signedhook.verify_with_replay`
    for the remaining parameters.
    """

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            payload = request.get_data()  # raw bytes, exactly as received
            headers = {name.lower(): value for name, value in request.headers.items()}
            try:
                if replay_cache is not None:
                    result = verify_with_replay(
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
            except SignedhookError as error:
                response = jsonify({"detail": {"code": error.code, "message": str(error)}})
                response.status_code = resolve_status(error)
                return response
            kwargs[result_kwarg] = result
            return view(*args, **kwargs)

        return wrapped

    return decorator

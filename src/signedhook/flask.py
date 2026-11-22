"""Optional Flask integration.

Install with ``pip install signedhook[flask]``. The decorator reads the raw
request body (cached, so the view can re-read it), verifies it with
signedhook, injects the :class:`~signedhook.VerificationResult` into the
view and converts failures into structured JSON responses with
machine-readable ``code`` fields and the same status semantics as the
FastAPI integration (413 too large, 400 malformed, 401 unauthenticated,
409 replayed, 500 misconfiguration).

With ``stream=True`` the decorator no longer buffers the body first: it
primes a :class:`~signedhook.StreamingVerifier` from the headers alone
(stale timestamps are rejected before a single body byte is read), then
feeds the WSGI input stream chunk by chunk while the HMAC state is updated
incrementally and the payload-size limit aborts the read mid-stream. The
body is re-injected afterwards, so ``request.get_data()``, ``request.form``
and ``request.get_json()`` keep working in the view.
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any

from ._errors import SignedhookError
from ._framework import DEFAULT_CHUNK_SIZE, feed_stream, read_capped, streaming_verifier_or_none
from ._http import resolve_status
from ._replay_check import apply_replay
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
    stream: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Build a view decorator that verifies webhook requests.

    Example:
        @app.post("/webhooks/stripe")
        @verify_webhook(provider="stripe", secrets=STRIPE_SECRET, stream=True)
        def stripe_events(result: VerificationResult) -> dict:
            return {"verified_provider": result.provider}

    On success the :class:`~signedhook.VerificationResult` is passed to the
    view as the ``result_kwarg`` keyword argument; declare it in the view
    signature. On failure the client receives
    ``{"detail": {"code": <stable code>, "message": <sanitised message>}}``
    with the mapped status.

    Args:
        result_kwarg: name of the view keyword argument that receives the
            verification result (default ``"result"``).
        stream: verify incrementally from the WSGI input stream instead of
            buffering the body first. Stale timestamps fail before any body
            byte is read; the payload-size limit aborts the read mid-stream.
            Schemes that cannot stream (Twilio) transparently fall back to
            a size-capped buffered read. The body is re-injected, so the
            view can still read it.
        chunk_size: body-read granularity in bytes for ``stream=True``.

    See :func:`signedhook.verify` / :func:`signedhook.verify_with_replay`
    for the remaining parameters.
    """

    def decorator(view: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(view)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
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
                        payload = feed_stream(verifier, request.stream.read, chunk_size)
                        result = verifier.finish()
                        if replay_cache is not None:
                            apply_replay(
                                replay_cache,
                                result,
                                key=key,
                                key_header=key_header,
                                headers=headers,
                                ttl_seconds=ttl_seconds,
                            )
                        # Re-inject the body: get_data(), form and json all
                        # read from this cache once the stream is consumed.
                        request._cached_data = payload
                        kwargs[result_kwarg] = result
                        return view(*args, **kwargs)
                    # Non-streamable scheme (e.g. Twilio): capped buffered read.
                    limit = (settings if settings is not None else Settings()).max_payload_bytes
                    payload = read_capped(request.stream.read, chunk_size, limit)
                    request._cached_data = payload
                else:
                    payload = request.get_data()  # raw bytes, exactly as received

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

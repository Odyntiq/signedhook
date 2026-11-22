"""Optional Django integration — webhook signature-verification middleware.

Install with ``pip install signedhook[django]``. Routes are configured
declaratively in ``settings.SIGNEDHOOK_ROUTES``; the middleware verifies
matching requests *before* they reach the view, attaches the
:class:`~signedhook.VerificationResult` as ``request.signedhook_result``
and turns failures into structured JSON responses with machine-readable
``code`` fields and the same status semantics as the FastAPI and Flask
integrations (413 too large, 400 malformed, 401 unauthenticated, 409
replayed, 500 misconfiguration).

Setup::

    MIDDLEWARE = [
        # ... before django.middleware.csrf.CsrfViewMiddleware
        "signedhook.django.WebhookMiddleware",
    ]

    SIGNEDHOOK_ROUTES = {
        "/webhooks/stripe/": {
            "provider": "stripe",
            "secrets": ["env:STRIPE_WEBHOOK_SECRET", "env:STRIPE_WEBHOOK_SECRET_OLD"],
            "tolerance": 300,
        },
        "/webhooks/github/": {
            "provider": "github",
            "secrets": "env:GITHUB_WEBHOOK_SECRET",
            "replay": True,                # per-process MemoryReplayCache
            "key_header": "x-github-delivery",
        },
        "/webhooks/big/": {
            "provider": "standard",
            "secrets": "env:BIG_WEBHOOK_SECRET",
            "stream": True,                # verify chunk by chunk
            "chunk_size": 65536,
        },
    }

Secrets given as ``"env:NAME"`` strings are resolved from the environment
at startup (fail-fast: a missing variable raises ``ConfigurationError``
during bootstrapping). Non-matching paths pass through untouched, so the
middleware costs one dict lookup per request on the rest of the site.

``"stream": True`` verifies incrementally instead of via ``request.body``:
the HMAC state is primed from the headers alone (stale timestamps are
rejected before a single body byte is read) and the body is read chunk by
chunk, with the payload-size limit aborting mid-stream. On WSGI
deployments this reads the socket-backed stream directly, so oversized or
unauthenticated deliveries are rejected before the rest of the body
arrives. Django's ASGI handler buffers the whole body before middleware
runs — for true wire-level streaming there, wrap the ASGI application with
:class:`SignedhookASGIMiddleware`::

    # asgi.py
    import django
    from django.core.asgi import get_asgi_application

    from signedhook.django import SignedhookASGIMiddleware

    django.setup(set_prefix=False)
    application = SignedhookASGIMiddleware(get_asgi_application())
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from collections.abc import AsyncGenerator, Awaitable, Callable, Mapping
from inspect import isawaitable
from typing import Any, cast

from ._encoding import normalize_secret_values
from ._errors import ConfigurationError, SignedhookError
from ._framework import (
    DEFAULT_CHUNK_SIZE,
    feed_stream,
    read_capped,
    read_capped_async,
    streaming_verifier_or_none,
)
from ._http import resolve_status
from ._replay_check import (
    apply_replay,
    apply_replay_async,
    is_async_replay_cache,
    is_replay_cache,
)
from ._settings import Settings
from ._types import VerificationResult
from .replay import AsyncReplayCache, MemoryReplayCache, ReplayCache
from .streaming import StreamingVerifier
from .verify import UNSET, UnsetType, verify, verify_with_replay

try:
    from django.http import HttpRequest, HttpResponse, JsonResponse
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "signedhook.django requires django — install with: pip install signedhook[django]"
    ) from exc

__all__ = ["SignedhookASGIMiddleware", "WebhookMiddleware"]

#: ASGI callables (scope, receive, send), spelled out locally because the
#: asgiref typing package is an optional dependency Django users may lack.
_Scope = dict[str, Any]
_Receive = Callable[[], Awaitable[_Scope]]
_Send = Callable[[_Scope], Awaitable[None]]


class _RouteConfig:
    """One verified route: normalised configuration plus its replay cache."""

    __slots__ = (
        "provider",
        "secrets",
        "tolerance",
        "settings",
        "replay_cache",
        "key_header",
        "ttl_seconds",
        "stream",
        "chunk_size",
    )

    def __init__(
        self,
        *,
        provider: str | None,
        secrets: tuple[str, ...],
        tolerance: int | None | UnsetType,
        settings: Settings,
        replay_cache: ReplayCache | AsyncReplayCache | None,
        key_header: str | None,
        ttl_seconds: float,
        stream: bool,
        chunk_size: int,
    ) -> None:
        self.provider = provider
        self.secrets = secrets
        self.tolerance = tolerance
        self.settings = settings
        self.replay_cache = replay_cache
        self.key_header = key_header
        self.ttl_seconds = ttl_seconds
        self.stream = stream
        self.chunk_size = chunk_size

    @classmethod
    def from_mapping(cls, path: str, config: Any) -> _RouteConfig:
        """Validate one ``SIGNEDHOOK_ROUTES`` entry, failing fast at startup."""
        if not isinstance(config, Mapping):
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}] must be a mapping of options, "
                f"got {type(config).__name__}"
            )
        unknown = set(config) - _SUPPORTED_KEYS
        if unknown:
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}] has unknown option(s): "
                f"{', '.join(sorted(unknown))} — supported: {', '.join(sorted(_SUPPORTED_KEYS))}"
            )

        provider = config.get("provider", "auto")
        if not isinstance(provider, str):
            raise ConfigurationError(f"SIGNEDHOOK_ROUTES[{path!r}]: 'provider' must be a string")

        tolerance = config.get("tolerance", UNSET)
        if not (
            isinstance(tolerance, UnsetType) or tolerance is None or isinstance(tolerance, int)
        ):
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}]: 'tolerance' must be an integer or null"
            )

        replay_raw = config.get("replay_cache")
        replay_enabled = config.get("replay", False)
        if replay_raw is None:
            replay_cache: ReplayCache | AsyncReplayCache | None = (
                MemoryReplayCache() if replay_enabled else None
            )
        elif is_replay_cache(replay_raw) or is_async_replay_cache(replay_raw):
            replay_cache = replay_raw
        elif callable(replay_raw):
            built = replay_raw()
            if not (is_replay_cache(built) or is_async_replay_cache(built)):  # pragma: no cover
                raise ConfigurationError(
                    f"SIGNEDHOOK_ROUTES[{path!r}]: 'replay_cache' factory returned "
                    "an object that does not implement a replay-cache protocol"
                )
            replay_cache = built
        else:
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}]: 'replay_cache' must be a replay cache "
                "instance or a zero-argument factory returning one"
            )

        key_header = config.get("key_header")
        if key_header is not None and not isinstance(key_header, str):
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}]: 'key_header' must be a header name"
            )

        ttl_seconds = config.get("ttl_seconds", 900)
        if not isinstance(ttl_seconds, (int, float)) or isinstance(ttl_seconds, bool):
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}]: 'ttl_seconds' must be a number of seconds"
            )

        max_payload = config.get("max_payload_bytes", Settings().max_payload_bytes)
        if not isinstance(max_payload, int) or isinstance(max_payload, bool):
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}]: 'max_payload_bytes' must be an integer"
            )
        try:
            route_settings = Settings(max_payload_bytes=max_payload)
        except ConfigurationError as exc:
            raise ConfigurationError(f"SIGNEDHOOK_ROUTES[{path!r}]: {exc}") from exc

        stream = config.get("stream", False)
        if not isinstance(stream, bool):
            raise ConfigurationError(f"SIGNEDHOOK_ROUTES[{path!r}]: 'stream' must be a boolean")

        chunk_size = config.get("chunk_size", DEFAULT_CHUNK_SIZE)
        if not isinstance(chunk_size, int) or isinstance(chunk_size, bool) or chunk_size < 1:
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}]: 'chunk_size' must be a positive integer"
            )

        return cls(
            provider=provider,
            secrets=_resolve_secrets(path, config.get("secrets")),
            tolerance=tolerance,
            settings=route_settings,
            replay_cache=replay_cache,
            key_header=key_header,
            ttl_seconds=float(ttl_seconds),
            stream=stream,
            chunk_size=chunk_size,
        )


#: Options accepted per route (validated eagerly so typos fail at boot).
_SUPPORTED_KEYS = {
    "provider",
    "secrets",
    "tolerance",
    "max_payload_bytes",
    "replay",
    "replay_cache",
    "key_header",
    "ttl_seconds",
    "stream",
    "chunk_size",
}


def _resolve_secrets(path: str, raw: Any) -> tuple[str, ...]:
    """Normalise a route's ``secrets`` option, resolving ``env:NAME`` values."""
    try:
        values = normalize_secret_values(raw)
    except (ConfigurationError, TypeError) as exc:
        raise ConfigurationError(f"SIGNEDHOOK_ROUTES[{path!r}]: invalid 'secrets' ({exc})") from exc
    resolved: list[str] = []
    for value in values:
        if value.startswith("env:"):
            name = value[len("env:") :]
            from_env = os.environ.get(name)
            if not from_env:
                raise ConfigurationError(
                    f"SIGNEDHOOK_ROUTES[{path!r}]: environment variable "
                    f"{name!r} for secrets is not set"
                )
            resolved.append(from_env)
        else:
            resolved.append(value)
    return tuple(resolved)


def _build_routes() -> dict[str, _RouteConfig]:
    """Read and validate ``SIGNEDHOOK_ROUTES`` from the configured settings."""
    from django.conf import settings

    routes = getattr(settings, "SIGNEDHOOK_ROUTES", {})
    if not isinstance(routes, Mapping):
        raise ConfigurationError("SIGNEDHOOK_ROUTES must be a mapping of path -> options")
    return {path: _RouteConfig.from_mapping(path, config) for path, config in routes.items()}


def _lowered_headers(request: HttpRequest) -> dict[str, str]:
    return {name.lower(): value for name, value in request.headers.items()}


def _restore_body(request: HttpRequest, payload: bytes) -> None:
    """Make a manually read body visible to the view again.

    Reading via ``request.read()`` marks the stream consumed; Django then
    raises ``RawPostDataException`` from ``request.body``. Resetting the
    same internals Django's own ``body`` property uses makes ``body``,
    ``POST`` and subsequent ``read()`` calls work as if nothing happened.
    """
    stream = getattr(request, "_stream", None)
    if stream is not None:
        # Servers may close inputs themselves (same close Django's own
        # ``body`` property performs after reading).
        with contextlib.suppress(OSError):
            stream.close()
    request._body = payload
    request._stream = io.BytesIO(payload)
    request._read_started = False


def _verify_buffered(
    payload: bytes,
    headers: dict[str, str],
    route: _RouteConfig,
) -> VerificationResult:
    """Buffered verification path shared by every mode."""
    cache = route.replay_cache
    if cache is None:
        return verify(
            payload,
            headers,
            secrets=route.secrets,
            provider=route.provider,
            tolerance=route.tolerance,
            settings=route.settings,
        )
    if is_async_replay_cache(cache):  # pragma: no cover - guarded by callers
        raise ConfigurationError("async replay caches require the ASGI middleware")
    return verify_with_replay(
        payload,
        headers,
        cast(ReplayCache, cache),
        secrets=route.secrets,
        provider=route.provider,
        tolerance=route.tolerance,
        settings=route.settings,
        key_header=route.key_header,
        ttl_seconds=route.ttl_seconds,
    )


class WebhookMiddleware:
    """Verify signed webhook deliveries for the paths in ``SIGNEDHOOK_ROUTES``.

    Place it in ``MIDDLEWARE`` before ``CsrfViewMiddleware``: webhook
    endpoints receive no CSRF token, so the middleware marks verified
    requests to skip the CSRF check (``request._dont_enforce_csrf_checks``,
    the same mechanism Django's test client uses). The request body is read
    as raw bytes and cached by Django, so the view still sees
    ``request.body``.

    With ``"stream": True`` on a route the body is instead read chunk by
    chunk and fed into a :class:`~signedhook.StreamingVerifier` (WSGI
    deployments stream straight off the socket); the body is restored
    afterwards, so ``request.body`` / ``request.POST`` still work.

    On ASGI deployments behind :class:`SignedhookASGIMiddleware`, requests
    the wrapper already verified arrive with the result stashed in
    ``request.scope["signedhook"]``; this middleware then attaches
    ``request.signedhook_result`` and skips CSRF without re-verifying.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response
        self._routes: dict[str, _RouteConfig] = _build_routes()

    def __call__(self, request: HttpRequest) -> HttpResponse:
        scope = getattr(request, "scope", None)
        preverified = scope.get("signedhook") if isinstance(scope, Mapping) else None
        if isinstance(preverified, VerificationResult):
            # Already verified wire-level by SignedhookASGIMiddleware.
            request.signedhook_result = preverified
            request._dont_enforce_csrf_checks = True
            return self.get_response(request)

        route = self._routes.get(request.path)
        if route is None:
            return self.get_response(request)

        headers = _lowered_headers(request)
        try:
            if route.stream:
                verifier = streaming_verifier_or_none(
                    headers,
                    secrets=route.secrets,
                    provider=route.provider,
                    tolerance=route.tolerance,
                    now=None,
                    settings=route.settings,
                )
                if verifier is not None:
                    result = self._verify_streaming(verifier, route, headers, request)
                else:
                    # Non-streamable scheme (e.g. Twilio): capped buffered read.
                    payload = read_capped(
                        request.read, route.chunk_size, route.settings.max_payload_bytes
                    )
                    result = _verify_buffered(payload, headers, route)
                    _restore_body(request, payload)
            else:
                payload = request.body  # raw bytes; Django caches it for the view
                result = _verify_buffered(payload, headers, route)
        except SignedhookError as error:
            response: HttpResponse = JsonResponse(
                {"detail": {"code": error.code, "message": str(error)}}
            )
            response.status_code = resolve_status(error)
            return response

        request.signedhook_result = result
        # Verified webhook deliveries carry no CSRF token; skip the CSRF
        # middleware for them (same flag Django's test client sets).
        request._dont_enforce_csrf_checks = True
        return self.get_response(request)

    def _verify_streaming(
        self,
        verifier: StreamingVerifier,
        route: _RouteConfig,
        headers: dict[str, str],
        request: HttpRequest,
    ) -> VerificationResult:
        """Feed the request stream into ``verifier`` and finish + replay-check."""
        payload = feed_stream(verifier, request.read, route.chunk_size)
        _restore_body(request, payload)
        result = verifier.finish()
        cache = route.replay_cache
        if cache is not None:
            if is_async_replay_cache(cache):  # pragma: no cover - guarded above
                raise ConfigurationError("async replay caches require the ASGI middleware")
            apply_replay(
                cast(ReplayCache, cache),
                result,
                key_header=route.key_header,
                headers=headers,
                ttl_seconds=route.ttl_seconds,
            )
        return result


class SignedhookASGIMiddleware:
    """ASGI wrapper that verifies webhook bodies as they arrive on the wire.

    Django's ASGI handler buffers the entire request body before any Django
    middleware runs, so ``WebhookMiddleware`` cannot stream on ASGI. This
    wrapper sits *around* the ASGI application instead::

        # asgi.py, after django.setup()
        application = SignedhookASGIMiddleware(get_asgi_application())

    It reads the same ``SIGNEDHOOK_ROUTES`` (lazily, since Django settings
    are configured after import time) and for matching paths intercepts
    ``receive()``: every ``http.request`` chunk feeds a
    :class:`~signedhook.StreamingVerifier` primed from the headers, so
    stale timestamps are rejected before any body byte is read and
    oversized deliveries abort mid-stream instead of after full
    buffering. Verified deliveries continue into the wrapped application
    with the body replayed and the result stashed in
    ``scope["signedhook"]``; install :class:`WebhookMiddleware` as well to
    attach ``request.signedhook_result`` and skip CSRF for them.

    Routes configured with ``"stream": False`` are verified here anyway —
    at the ASGI layer streaming is strictly better; the flag only governs
    the Django middleware's WSGI behaviour. Replay caches may be sync or
    async (async stores are awaited; the event loop is never blocked).
    """

    def __init__(self, app: Callable[..., Any]) -> None:
        self.app = app
        self._routes: dict[str, _RouteConfig] | None = None

    def _get_routes(self) -> dict[str, _RouteConfig]:
        if self._routes is None:
            self._routes = _build_routes()
        return self._routes

    async def __call__(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        if scope.get("type") != "http":
            await self._call_app(scope, receive, send)
            return
        try:
            routes = self._get_routes()
        except SignedhookError as error:  # malformed SIGNEDHOOK_ROUTES
            await _send_asgi_error(send, error)
            return
        route = routes.get(scope.get("path", ""))
        if route is None:
            await self._call_app(scope, receive, send)
            return

        headers = {
            name.decode("latin-1").lower(): value.decode("latin-1")
            for name, value in scope.get("headers", [])
        }
        try:
            verifier = streaming_verifier_or_none(
                headers,
                secrets=route.secrets,
                provider=route.provider,
                tolerance=route.tolerance,
                now=None,
                settings=route.settings,
            )
            if verifier is None:
                # Non-streamable scheme (e.g. Twilio): capped buffered read
                # from the wire, then buffered verification.
                payload = await read_capped_async(
                    _body_messages(receive), route.settings.max_payload_bytes
                )
                result = _verify_buffered(payload, headers, route)
            else:
                chunks: list[bytes] = []
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return  # client went away mid-body; nothing to answer
                    body = message.get("body", b"")
                    if body:
                        verifier.feed(body)
                        chunks.append(body)
                    if not message.get("more_body", False):
                        break
                result = verifier.finish()
                payload = b"".join(chunks)
            cache = route.replay_cache
            if cache is not None:
                if is_async_replay_cache(cache):
                    await apply_replay_async(
                        cast(AsyncReplayCache, cache),
                        result,
                        key_header=route.key_header,
                        headers=headers,
                        ttl_seconds=route.ttl_seconds,
                    )
                else:
                    apply_replay(
                        cast(ReplayCache, cache),
                        result,
                        key_header=route.key_header,
                        headers=headers,
                        ttl_seconds=route.ttl_seconds,
                    )
        except SignedhookError as error:
            await _send_asgi_error(send, error)
            return

        scope["signedhook"] = result
        replayed = {"done": False}

        async def replay_receive() -> _Scope:
            if not replayed["done"]:
                replayed["done"] = True
                return {"type": "http.request", "body": payload, "more_body": False}
            return await receive()  # forward disconnects / anything after the body

        await self._call_app(scope, replay_receive, send)

    async def _call_app(self, scope: _Scope, receive: _Receive, send: _Send) -> None:
        result = self.app(scope, receive, send)
        if isawaitable(result):  # ASGI apps return awaitables (usually coroutines)
            await result


async def _body_messages(receive: _Receive) -> AsyncGenerator[bytes, None]:
    """Yield body chunks from the receive channel until the body ends."""
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return
        if message["type"] == "http.request":
            body = message.get("body", b"")
            if body:
                yield body
            if not message.get("more_body", False):
                return


async def _send_asgi_error(send: _Send, error: SignedhookError) -> None:
    """Send the shared structured JSON error response at the ASGI layer."""
    payload = json.dumps({"detail": {"code": error.code, "message": str(error)}}).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": resolve_status(error),
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": payload})

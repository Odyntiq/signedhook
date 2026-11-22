"""Optional Django integration — webhook signature-verification middleware.

Install with ``pip install signedhook[django]``. Routes are configured
declaratively in ``settings.SIGNEDHOOK_ROUTES``; the middleware verifies
matching requests *before* they reach the view, attaches the
:class:`~signedhook.VerificationResult` as ``request.signedhook_result``
and turns failures into structured JSON responses with machine-readable
``code`` fields and the same status semantics as the FastAPI and Flask
integrations (413 too large, 400 malformed, 401 unauthenticated,
409 replayed, 500 misconfiguration).

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
    }

Secrets given as ``"env:NAME"`` strings are resolved from the environment
at startup (fail-fast: a missing variable raises ``ConfigurationError``
during bootstrapping). Non-matching paths pass through untouched, so the
middleware costs one dict lookup per request on the rest of the site.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from typing import Any

from ._encoding import normalize_secret_values
from ._errors import ConfigurationError, SignedhookError
from ._http import resolve_status
from ._replay_check import is_replay_cache
from ._settings import Settings
from .replay import MemoryReplayCache, ReplayCache
from .verify import UNSET, UnsetType, verify, verify_with_replay

try:
    from django.http import HttpRequest, HttpResponse, JsonResponse
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "signedhook.django requires django — install with: pip install signedhook[django]"
    ) from exc

__all__ = ["WebhookMiddleware"]


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
    )

    def __init__(
        self,
        *,
        provider: str | None,
        secrets: tuple[str, ...],
        tolerance: int | None | UnsetType,
        settings: Settings,
        replay_cache: ReplayCache | None,
        key_header: str | None,
        ttl_seconds: float,
    ) -> None:
        self.provider = provider
        self.secrets = secrets
        self.tolerance = tolerance
        self.settings = settings
        self.replay_cache = replay_cache
        self.key_header = key_header
        self.ttl_seconds = ttl_seconds

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
            replay_cache: ReplayCache | None = MemoryReplayCache() if replay_enabled else None
        elif is_replay_cache(replay_raw):
            replay_cache = replay_raw
        elif callable(replay_raw):
            built = replay_raw()
            if not is_replay_cache(built):  # pragma: no cover - defensive
                raise ConfigurationError(
                    f"SIGNEDHOOK_ROUTES[{path!r}]: 'replay_cache' factory returned "
                    "an object that does not implement the ReplayCache protocol"
                )
            replay_cache = built
        else:
            raise ConfigurationError(
                f"SIGNEDHOOK_ROUTES[{path!r}]: 'replay_cache' must be a ReplayCache "
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

        return cls(
            provider=provider,
            secrets=_resolve_secrets(path, config.get("secrets")),
            tolerance=tolerance,
            settings=route_settings,
            replay_cache=replay_cache,
            key_header=key_header,
            ttl_seconds=float(ttl_seconds),
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


class WebhookMiddleware:
    """Verify signed webhook deliveries for the paths in ``SIGNEDHOOK_ROUTES``.

    Place it in ``MIDDLEWARE`` before ``CsrfViewMiddleware``: webhook
    endpoints receive no CSRF token, so the middleware marks verified
    requests to skip the CSRF check (``request._dont_enforce_csrf_checks``,
    the same mechanism Django's test client uses). The request body is read
    as raw bytes and cached by Django, so the view still sees ``request.body``.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        from django.conf import settings

        self.get_response = get_response
        routes = getattr(settings, "SIGNEDHOOK_ROUTES", {})
        if not isinstance(routes, Mapping):
            raise ConfigurationError("SIGNEDHOOK_ROUTES must be a mapping of path -> options")
        self._routes: dict[str, _RouteConfig] = {
            path: _RouteConfig.from_mapping(path, config) for path, config in routes.items()
        }

    def __call__(self, request: HttpRequest) -> HttpResponse:
        route = self._routes.get(request.path)
        if route is None:
            return self.get_response(request)
        try:
            payload = request.body  # raw bytes; Django caches it for the view
            headers = {name.lower(): value for name, value in request.headers.items()}
            if route.replay_cache is not None:
                result = verify_with_replay(
                    payload,
                    headers,
                    route.replay_cache,
                    secrets=route.secrets,
                    provider=route.provider,
                    tolerance=route.tolerance,
                    settings=route.settings,
                    key_header=route.key_header,
                    ttl_seconds=route.ttl_seconds,
                )
            else:
                result = verify(
                    payload,
                    headers,
                    secrets=route.secrets,
                    provider=route.provider,
                    tolerance=route.tolerance,
                    settings=route.settings,
                )
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

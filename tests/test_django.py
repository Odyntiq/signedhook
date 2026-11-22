"""Django integration: middleware verification, error mapping and replay."""

from __future__ import annotations

import json
import time
from typing import Any

import pytest

django = pytest.importorskip("django")

from django.conf import settings as dj_settings  # noqa: E402
from django.http import HttpResponse  # noqa: E402
from django.test import RequestFactory  # noqa: E402

from conftest import GH_SECRET, PAYLOAD, STD_SECRET_HEADER, hmac_sha256_hex  # noqa: E402
from signedhook import (  # noqa: E402
    ConfigurationError,
    MemoryReplayCache,
    VerificationResult,
    sign,
)
from signedhook.django import WebhookMiddleware  # noqa: E402


def configure(**options: Any) -> None:
    if not dj_settings.configured:
        dj_settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], SIGNEDHOOK_ROUTES={})
    for name, value in options.items():
        setattr(dj_settings, name, value)


def as_django_headers(headers: dict[str, str]) -> dict[str, str]:
    """Normalise header names for RequestFactory's ``headers=`` mapping."""
    return {name.replace("_", "-").lower(): value for name, value in headers.items()}


def fresh_std_headers(payload: bytes = PAYLOAD, webhook_id: str = "msg_1") -> dict[str, str]:
    return sign(payload, secret=STD_SECRET_HEADER, webhook_id=webhook_id)


def make_middleware(routes: dict[str, Any]) -> WebhookMiddleware:
    configure(SIGNEDHOOK_ROUTES=routes)
    captured: dict[str, Any] = {}

    def get_response(request: Any) -> HttpResponse:
        captured["request"] = request
        return HttpResponse("ok")

    middleware = WebhookMiddleware(get_response)
    middleware.captured = captured  # type: ignore[attr-defined]
    return middleware


def detail(response: Any) -> dict[str, str]:
    """Parse a middleware JsonResponse body (it has no .json() helper)."""
    return json.loads(response.content)["detail"]


@pytest.fixture()
def factory() -> RequestFactory:
    configure()
    return RequestFactory()


class TestHappyPath:
    def test_valid_delivery_passes_result_to_view(self, factory: RequestFactory) -> None:
        middleware = make_middleware(
            {
                "/webhooks/std/": {
                    "provider": "standard",
                    "secrets": STD_SECRET_HEADER,
                    "tolerance": 300,
                }
            }
        )
        request = factory.post(
            "/webhooks/std/",
            data=PAYLOAD,
            content_type="application/json",
            headers=as_django_headers(fresh_std_headers()),
        )
        response = middleware(request)
        assert response.status_code == 200
        assert b"ok" in response.content
        result = middleware.captured["request"].signedhook_result  # type: ignore[attr-defined]
        assert result.provider == "standard"
        assert result.payload_size == len(PAYLOAD)

    def test_csrf_check_disabled_for_verified_routes(self, factory: RequestFactory) -> None:
        middleware = make_middleware(
            {"/webhooks/gh/": {"provider": "github", "secrets": GH_SECRET}}
        )
        request = factory.post(
            "/webhooks/gh/",
            data=PAYLOAD,
            content_type="application/json",
            headers={"x-hub-signature-256": f"sha256={hmac_sha256_hex(GH_SECRET, PAYLOAD)}"},
        )
        middleware(request)
        assert request._dont_enforce_csrf_checks is True  # type: ignore[attr-defined]

    def test_non_matching_paths_pass_through(self, factory: RequestFactory) -> None:
        middleware = make_middleware({"/webhooks/std/": {"secrets": STD_SECRET_HEADER}})
        request = factory.post("/api/unrelated/", data=b"{}", content_type="application/json")
        response = middleware(request)
        assert response.status_code == 200

    def test_env_secret_resolution(
        self, factory: RequestFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIGNEDHOOK_TEST_STD_SECRET", STD_SECRET_HEADER)
        middleware = make_middleware(
            {"/webhooks/std/": {"secrets": "env:SIGNEDHOOK_TEST_STD_SECRET"}}
        )
        request = factory.post(
            "/webhooks/std/",
            data=PAYLOAD,
            content_type="application/json",
            headers=as_django_headers(fresh_std_headers()),
        )
        assert middleware(request).status_code == 200

    def test_rotation_with_env_and_literal_secrets(
        self, factory: RequestFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIGNEDHOOK_TEST_STD_OLD", "wrong-old-secret")
        middleware = make_middleware(
            {
                "/webhooks/std/": {
                    "secrets": ["env:SIGNEDHOOK_TEST_STD_OLD", STD_SECRET_HEADER],
                }
            }
        )
        request = factory.post(
            "/webhooks/std/",
            data=PAYLOAD,
            content_type="application/json",
            headers=as_django_headers(fresh_std_headers()),
        )
        middleware(request)
        result = middleware.captured["request"].signedhook_result  # type: ignore[attr-defined]
        assert result.matched_secret_index == 1

    def test_per_route_max_payload_bytes(self, factory: RequestFactory) -> None:
        body = b"x" * 400
        middleware = make_middleware(
            {
                "/webhooks/std/": {
                    "secrets": STD_SECRET_HEADER,
                    "max_payload_bytes": 300,
                }
            }
        )
        request = factory.post(
            "/webhooks/std/",
            data=body,
            content_type="application/json",
            headers=as_django_headers(sign(body, secret=STD_SECRET_HEADER, webhook_id="msg_big")),
        )
        response = middleware(request)
        assert response.status_code == 413
        assert detail(response)["code"] == "payload_too_large"


class TestErrorMapping:
    def post_std(
        self,
        factory: RequestFactory,
        routes: dict[str, Any],
        body: bytes,
        headers: dict[str, str],
    ) -> Any:
        middleware = make_middleware(routes)
        request = factory.post(
            "/webhooks/std/",
            data=body,
            content_type="application/json",
            headers=as_django_headers(headers),
        )
        return middleware(request)

    def test_bad_signature_is_401(self, factory: RequestFactory) -> None:
        headers = fresh_std_headers()
        headers["webhook-signature"] = "v1,AAAA"
        response = self.post_std(
            factory, {"/webhooks/std/": {"secrets": STD_SECRET_HEADER}}, PAYLOAD, headers
        )
        assert response.status_code == 401
        assert detail(response)["code"] == "signature_mismatch"

    def test_missing_header_is_400_in_strict_mode(self, factory: RequestFactory) -> None:
        # Strict mode names the scheme, so the precise missing header error
        # (400) surfaces instead of the auto-detection failure (401).
        response = self.post_std(
            factory,
            {"/webhooks/std/": {"provider": "standard", "secrets": STD_SECRET_HEADER}},
            PAYLOAD,
            {"webhook-id": "msg_1"},
        )
        assert response.status_code == 400
        assert detail(response)["code"] == "missing_header"

    def test_stale_timestamp_is_401(self, factory: RequestFactory) -> None:
        stale = sign(
            PAYLOAD,
            secret=STD_SECRET_HEADER,
            webhook_id="msg_stale",
            now=int(time.time()) - 10_000,
        )
        response = self.post_std(
            factory,
            {"/webhooks/std/": {"secrets": STD_SECRET_HEADER}},
            PAYLOAD,
            stale,
        )
        assert response.status_code == 401
        assert detail(response)["code"] == "timestamp_outside_tolerance"

    def test_missing_env_variable_fails_fast_at_startup(self) -> None:
        configure()
        with pytest.raises(ConfigurationError) as excinfo:
            make_middleware({"/webhooks/std/": {"secrets": "env:SIGNEDHOOK_NOPE"}})
        assert "SIGNEDHOOK_NOPE" in str(excinfo.value)

    def test_unknown_route_option_rejected(self) -> None:
        configure()
        with pytest.raises(ConfigurationError) as excinfo:
            make_middleware({"/webhooks/std/": {"secrets": "s", "providr": "stripe"}})
        assert "providr" in str(excinfo.value)

    def test_invalid_max_payload_rejected(self) -> None:
        configure()
        with pytest.raises(ConfigurationError) as excinfo:
            make_middleware({"/webhooks/std/": {"secrets": "s", "max_payload_bytes": 10}})
        assert "max_payload_bytes" in str(excinfo.value)


class TestReplay:
    def test_second_delivery_is_409(self, factory: RequestFactory) -> None:
        middleware = make_middleware(
            {"/webhooks/std/": {"secrets": STD_SECRET_HEADER, "replay": True}}
        )
        headers = as_django_headers(fresh_std_headers(webhook_id="msg_replay"))
        first = middleware(
            factory.post(
                "/webhooks/std/", data=PAYLOAD, content_type="application/json", headers=headers
            )
        )
        second = middleware(
            factory.post(
                "/webhooks/std/", data=PAYLOAD, content_type="application/json", headers=headers
            )
        )
        assert first.status_code == 200
        assert second.status_code == 409
        assert detail(second)["code"] == "replay_rejected"

    def test_replay_cache_factory(self, factory: RequestFactory) -> None:
        shared = MemoryReplayCache()
        middleware = make_middleware(
            {
                "/webhooks/std/": {
                    "secrets": STD_SECRET_HEADER,
                    "replay_cache": lambda: shared,
                }
            }
        )
        headers = as_django_headers(fresh_std_headers(webhook_id="msg_factory"))
        middleware(
            factory.post(
                "/webhooks/std/", data=PAYLOAD, content_type="application/json", headers=headers
            )
        )
        assert shared.seen_within("msg_factory", 900) is True


class TestStreamingRoutes:
    """ "stream": True — incremental verification with the body restored."""

    STD_STREAM_ROUTE = {
        "provider": "standard",
        "secrets": STD_SECRET_HEADER,
        "tolerance": 300,
        "stream": True,
    }

    def test_verified_delivery_restores_body_for_view(self, factory: RequestFactory) -> None:
        middleware = make_middleware({"/webhooks/std/": dict(self.STD_STREAM_ROUTE)})
        request = factory.post(
            "/webhooks/std/",
            data=PAYLOAD,
            content_type="application/json",
            headers=as_django_headers(fresh_std_headers()),
        )
        response = middleware(request)
        assert response.status_code == 200
        captured = middleware.captured["request"]
        result = captured.signedhook_result
        assert result.provider == "standard"
        assert result.payload_size == len(PAYLOAD)
        # The view reads the body normally despite the manual stream read.
        assert captured.body == PAYLOAD
        # The restored stream is re-readable: read() yields the body again.
        assert captured.read() == PAYLOAD

    def test_form_parsing_works_after_streaming(self, factory: RequestFactory) -> None:
        body = b"a=1&b=2"
        headers = sign(body, secret=STD_SECRET_HEADER, webhook_id="msg_form")
        middleware = make_middleware({"/webhooks/std/": dict(self.STD_STREAM_ROUTE)})

        def get_response(request: Any) -> HttpResponse:
            return HttpResponse(
                json.dumps({"form": dict(request.POST.items())}), content_type="application/json"
            )

        middleware.get_response = get_response
        request = factory.post(
            "/webhooks/std/",
            data=body,
            content_type="application/x-www-form-urlencoded",
            headers=as_django_headers(headers),
        )
        response = middleware(request)
        assert response.status_code == 200
        assert json.loads(response.content) == {"form": {"a": "1", "b": "2"}}

    def test_tampered_signature_is_401(self, factory: RequestFactory) -> None:
        middleware = make_middleware({"/webhooks/std/": dict(self.STD_STREAM_ROUTE)})
        headers = fresh_std_headers()
        headers["webhook-signature"] = "v1,AAAA"
        request = factory.post(
            "/webhooks/std/",
            data=b'{"event":"tampered"}',
            content_type="application/json",
            headers=as_django_headers(headers),
        )
        response = middleware(request)
        assert response.status_code == 401
        assert detail(response)["code"] == "signature_mismatch"

    def test_oversized_body_is_413(self, factory: RequestFactory) -> None:
        middleware = make_middleware(
            {
                "/webhooks/std/": {
                    **self.STD_STREAM_ROUTE,
                    "max_payload_bytes": 256,
                    "chunk_size": 100,
                }
            }
        )
        body = b"x" * 1000
        headers = sign(body, secret=STD_SECRET_HEADER, webhook_id="msg_big")
        request = factory.post(
            "/webhooks/std/",
            data=body,
            content_type="application/json",
            headers=as_django_headers(headers),
        )
        response = middleware(request)
        assert response.status_code == 413
        assert detail(response)["code"] == "payload_too_large"

    def test_replay_is_409(self, factory: RequestFactory) -> None:
        middleware = make_middleware({"/webhooks/std/": {**self.STD_STREAM_ROUTE, "replay": True}})
        headers = fresh_std_headers()
        for _ in range(2):
            request = factory.post(
                "/webhooks/std/",
                data=PAYLOAD,
                content_type="application/json",
                headers=as_django_headers(headers),
            )
            response = middleware(request)
        assert response.status_code == 409
        assert detail(response)["code"] == "replay_rejected"

    def test_chunk_size_one_still_verifies(self, factory: RequestFactory) -> None:
        middleware = make_middleware({"/webhooks/std/": {**self.STD_STREAM_ROUTE, "chunk_size": 1}})
        request = factory.post(
            "/webhooks/std/",
            data=PAYLOAD,
            content_type="application/json",
            headers=as_django_headers(fresh_std_headers()),
        )
        assert middleware(request).status_code == 200

    def test_twilio_falls_back_to_buffered_behaviour(self, factory: RequestFactory) -> None:
        for stream in (False, True):
            middleware = make_middleware(
                {"/webhooks/tw/": {"provider": "twilio", "secrets": "token", "stream": stream}}
            )
            request = factory.post(
                "/webhooks/tw/",
                data=b"a=1",
                content_type="application/x-www-form-urlencoded",
                headers={"x-twilio-signature": "AAAA"},
            )
            response = middleware(request)
            assert response.status_code == 500, stream
            assert detail(response)["code"] == "configuration_error"

    def test_twilio_fallback_enforces_size_cap(self, factory: RequestFactory) -> None:
        middleware = make_middleware(
            {
                "/webhooks/tw/": {
                    "provider": "twilio",
                    "secrets": "token",
                    "stream": True,
                    "max_payload_bytes": 256,
                }
            }
        )
        request = factory.post(
            "/webhooks/tw/",
            data=b"x" * 400,
            content_type="application/x-www-form-urlencoded",
            headers={"x-twilio-signature": "AAAA"},
        )
        response = middleware(request)
        assert response.status_code == 413
        assert detail(response)["code"] == "payload_too_large"

    def test_stream_option_validation(self) -> None:
        with pytest.raises(ConfigurationError):
            make_middleware({"/w/": {"secrets": "s", "stream": "yes"}})
        with pytest.raises(ConfigurationError):
            make_middleware({"/w/": {"secrets": "s", "stream": True, "chunk_size": 0}})
        with pytest.raises(ConfigurationError):
            make_middleware({"/w/": {"secrets": "s", "stream": True, "chunk_size": True}})


class TestScopeTrust:
    """WebhookMiddleware picks up results pre-verified by the ASGI wrapper."""

    def test_preverified_scope_skips_verification(self, factory: RequestFactory) -> None:
        middleware = make_middleware({"/webhooks/std/": {"secrets": STD_SECRET_HEADER}})
        request = factory.post("/webhooks/std/", data=b"{}", content_type="application/json")
        request.scope = {
            "signedhook": VerificationResult(  # type: ignore[attr-defined]
                provider="standard",
                scheme="hmac-sha256",
                timestamp=1700000000,
                matched_secret_index=0,
                message_key="msg_pre",
                payload_size=2,
            )
        }
        response = middleware(request)
        assert response.status_code == 200
        captured = middleware.captured["request"]
        assert captured.signedhook_result.message_key == "msg_pre"
        assert captured._dont_enforce_csrf_checks is True

    def test_scope_with_foreign_value_is_ignored(self, factory: RequestFactory) -> None:
        middleware = make_middleware({"/webhooks/std/": {"secrets": STD_SECRET_HEADER}})
        request = factory.post(
            "/webhooks/std/",
            data=PAYLOAD,
            content_type="application/json",
            headers=as_django_headers(fresh_std_headers(webhook_id="msg_1")),
        )
        request.scope = {"signedhook": "not-a-result"}  # type: ignore[attr-defined]
        # Falls through to normal verification: signature is valid, so 200.
        assert middleware(request).status_code == 200


class TestASGIRequestStreaming:
    """Stream mode also works for Django's ASGI request objects."""

    def test_asgi_request_stream_route_verifies_and_restores_body(self) -> None:
        from django.test import AsyncRequestFactory

        middleware = make_middleware({"/webhooks/std/": dict(TestStreamingRoutes.STD_STREAM_ROUTE)})
        async_factory = AsyncRequestFactory()
        request = async_factory.post(
            "/webhooks/std/",
            data=PAYLOAD,
            content_type="application/json",
            headers=as_django_headers(fresh_std_headers()),
        )
        response = middleware(request)
        assert response.status_code == 200
        captured = middleware.captured["request"]
        assert captured.signedhook_result.provider == "standard"
        assert captured.body == PAYLOAD

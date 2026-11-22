"""FastAPI integration tests (skipped when fastapi/httpx are unavailable)."""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient

from fastapi import Depends, FastAPI, Request  # noqa: E402

from conftest import NOW, PAYLOAD, STD_SECRET_HEADER, std_headers  # noqa: E402
from signedhook import (  # noqa: E402
    AsyncMemoryReplayCache,
    MemoryReplayCache,
    Settings,
    SignatureMismatchError,
    TimestampToleranceExceededError,
)
from signedhook.fastapi import webhook_dependency  # noqa: E402


def build_app(**dep_kwargs: object) -> TestClient:
    app = FastAPI()
    dependency = webhook_dependency(**dep_kwargs)  # type: ignore[arg-type]

    @app.post("/hook")
    async def hook(result: object = Depends(dependency)) -> dict[str, object]:
        return {"provider": getattr(result, "provider", None)}

    return TestClient(app)


def test_verified_request_returns_result() -> None:
    client = build_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW)
    response = client.post("/hook", content=PAYLOAD, headers=std_headers())
    assert response.status_code == 200
    assert response.json() == {"provider": "standard"}


def test_tampered_payload_is_401_with_code() -> None:
    client = build_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW)
    response = client.post("/hook", content=b"tampered", headers=std_headers())
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "signature_mismatch"


def test_missing_headers_are_400() -> None:
    client = build_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW)
    response = client.post("/hook", content=PAYLOAD, headers={"webhook-id": "msg_x"})
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "missing_header"


def test_timestamp_beyond_tolerance_is_401() -> None:
    client = build_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW + 301)
    response = client.post("/hook", content=PAYLOAD, headers=std_headers())
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "timestamp_outside_tolerance"


def test_tolerance_error_type_map() -> None:
    assert isinstance(TimestampToleranceExceededError("x", 1), TimestampToleranceExceededError)


def test_replay_is_409() -> None:
    client = build_app(
        provider="standard",
        secrets=STD_SECRET_HEADER,
        now=NOW,
        replay_cache=MemoryReplayCache(),
    )
    first = client.post("/hook", content=PAYLOAD, headers=std_headers())
    assert first.status_code == 200
    second = client.post("/hook", content=PAYLOAD, headers=std_headers())
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "replay_rejected"


def test_payload_limit_is_413() -> None:
    client = build_app(
        provider="standard",
        secrets=STD_SECRET_HEADER,
        now=NOW,
        settings=Settings(max_payload_bytes=256),
    )
    response = client.post("/hook", content=b"y" * 300, headers=std_headers())
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "payload_too_large"


def test_status_overrides_apply() -> None:
    client = build_app(
        provider="standard",
        secrets=STD_SECRET_HEADER,
        now=NOW,
        status_overrides={SignatureMismatchError: 418},
    )
    response = client.post("/hook", content=b"tampered", headers=std_headers())
    assert response.status_code == 418


def test_auto_provider_mode_works() -> None:
    client = build_app(secrets=STD_SECRET_HEADER, now=NOW)
    response = client.post("/hook", content=PAYLOAD, headers=std_headers())
    assert response.status_code == 200
    assert response.json() == {"provider": "standard"}


def test_async_replay_cache_is_awaited() -> None:
    # An AsyncReplayCache must be detected and awaited rather than called
    # synchronously — the second delivery is rejected with 409.
    client = build_app(
        provider="standard",
        secrets=STD_SECRET_HEADER,
        now=NOW,
        replay_cache=AsyncMemoryReplayCache(),
    )
    first = client.post("/hook", content=PAYLOAD, headers=std_headers())
    assert first.status_code == 200
    second = client.post("/hook", content=PAYLOAD, headers=std_headers())
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "replay_rejected"


def test_async_cache_never_blocks_unauthenticated_traffic() -> None:
    cache = AsyncMemoryReplayCache()
    client = build_app(
        provider="standard",
        secrets=STD_SECRET_HEADER,
        now=NOW,
        replay_cache=cache,
    )
    response = client.post("/hook", content=b"tampered", headers=std_headers())
    assert response.status_code == 401
    assert len(cache) == 0


# --- Streaming mode -----------------------------------------------------------


def build_stream_app(**dep_kwargs: object) -> TestClient:
    """App whose route declares a parsed body model, proving re-injection."""
    app = FastAPI()
    dependency = webhook_dependency(**dep_kwargs)  # type: ignore[arg-type]

    @app.post("/hook")
    async def hook(event: dict, result: object = Depends(dependency)) -> dict[str, object]:
        return {"provider": getattr(result, "provider", None), "event": event}

    return TestClient(app)


def json_headers(overrides: dict[str, str] | None = None) -> dict[str, str]:
    """Signed Standard Webhooks headers plus a JSON content type."""
    headers = std_headers()
    headers["content-type"] = "application/json"
    if overrides:
        headers.update(overrides)
    return headers


def test_stream_verified_request_parses_body() -> None:
    client = build_stream_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW, stream=True)
    response = client.post("/hook", content=PAYLOAD, headers=json_headers())
    assert response.status_code == 200
    body = response.json()
    assert body["provider"] == "standard"
    assert body["event"] == {"event": "ping", "seq": 1}


def test_stream_route_without_body_model_feeds_the_stream_directly() -> None:
    # Without body parameters FastAPI does not pre-read the body, so the
    # dependency consumes request.stream() itself; the handler can still read
    # the body afterwards because the dependency re-injects it.
    app = FastAPI()
    dependency = webhook_dependency(  # type: ignore[arg-type]
        provider="standard", secrets=STD_SECRET_HEADER, now=NOW, stream=True
    )

    @app.post("/hook")
    async def hook(request: Request, result: object = Depends(dependency)) -> dict[str, object]:
        return {
            "provider": getattr(result, "provider", None),
            "body": (await request.body()).decode(),
        }

    client = TestClient(app)
    response = client.post("/hook", content=PAYLOAD, headers=json_headers())
    assert response.status_code == 200
    assert response.json() == {"provider": "standard", "body": PAYLOAD.decode()}


def test_stream_tampered_payload_is_401() -> None:
    client = build_stream_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW, stream=True)
    tampered = b'{"event":"tampered"}'  # valid JSON: body parsing must not 422 first
    response = client.post("/hook", content=tampered, headers=json_headers())
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "signature_mismatch"


def test_stream_payload_limit_is_413() -> None:
    client = build_stream_app(
        provider="standard",
        secrets=STD_SECRET_HEADER,
        now=NOW,
        stream=True,
        settings=Settings(max_payload_bytes=256),
    )
    big = b'{"pad":"' + b"y" * 280 + b'"}'  # valid JSON over the limit
    response = client.post("/hook", content=big, headers=json_headers())
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "payload_too_large"


def test_stream_stale_timestamp_is_401() -> None:
    client = build_stream_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW, stream=True)
    response = client.post(
        "/hook",
        content=PAYLOAD,
        headers=json_headers({"webhook-timestamp": str(NOW - 10_000)}),
    )
    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "timestamp_outside_tolerance"


def test_stream_replay_with_sync_cache_is_409() -> None:
    client = build_stream_app(
        provider="standard",
        secrets=STD_SECRET_HEADER,
        now=NOW,
        stream=True,
        replay_cache=MemoryReplayCache(),
    )
    first = client.post("/hook", content=PAYLOAD, headers=json_headers())
    second = client.post("/hook", content=PAYLOAD, headers=json_headers())
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "replay_rejected"


def test_stream_replay_with_async_cache_is_409() -> None:
    client = build_stream_app(
        provider="standard",
        secrets=STD_SECRET_HEADER,
        now=NOW,
        stream=True,
        replay_cache=AsyncMemoryReplayCache(),
    )
    first = client.post("/hook", content=PAYLOAD, headers=json_headers())
    second = client.post("/hook", content=PAYLOAD, headers=json_headers())
    assert first.status_code == 200
    assert second.status_code == 409


def test_stream_matches_buffered_outcome() -> None:
    for client in (
        build_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW),
        build_stream_app(provider="standard", secrets=STD_SECRET_HEADER, now=NOW, stream=True),
    ):
        ok = client.post("/hook", content=PAYLOAD, headers=json_headers())
        bad = client.post("/hook", content=b'{"event":"tampered"}', headers=json_headers())
        assert ok.status_code == 200
        assert bad.status_code == 401


def test_stream_twilio_falls_back_to_buffered_error() -> None:
    # Twilio signs URL + form parameters, so streaming is impossible; the
    # dependency falls back to the buffered path and reports the same error.
    buffered = build_app(provider="twilio", secrets="token", now=NOW)
    streaming = build_stream_app(provider="twilio", secrets="token", now=NOW, stream=True)
    headers = {"x-twilio-signature": "AAAA"}
    buffered_response = buffered.post("/hook", content=b"a=1", headers=headers)
    streaming_response = streaming.post("/hook", content=b"a=1", headers=headers)
    assert buffered_response.status_code == streaming_response.status_code
    assert buffered_response.json()["detail"]["code"] == streaming_response.json()["detail"]["code"]


def test_stream_fallback_enforces_size_cap_mid_stream() -> None:
    client = build_stream_app(
        provider="twilio",
        secrets="token",
        now=NOW,
        stream=True,
        settings=Settings(max_payload_bytes=256),
    )
    response = client.post("/hook", content=b"z" * 300, headers={"x-twilio-signature": "AAAA"})
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "payload_too_large"

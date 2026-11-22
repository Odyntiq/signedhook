"""FastAPI integration tests (skipped when fastapi/httpx are unavailable)."""

from __future__ import annotations

import pytest

fastapi = pytest.importorskip("fastapi")
TestClient = pytest.importorskip("fastapi.testclient").TestClient

from fastapi import Depends, FastAPI  # noqa: E402

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

"""SignedhookASGIMiddleware: wire-level streaming verification for Django ASGI.

Async tests run through ``asyncio.run`` inside plain sync test functions (no
async plugin needed), with fake ASGI receive/send channels. The fakes count
receive calls, which makes the streaming guarantees observable: stale
timestamps must not pull a single body message, oversized deliveries must
abort mid-body, and tampered ones must never reach the wrapped application.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import pytest

django = pytest.importorskip("django")

from django.conf import settings as dj_settings  # noqa: E402

from conftest import PAYLOAD, STD_SECRET_HEADER  # noqa: E402
from signedhook import (  # noqa: E402
    AsyncMemoryReplayCache,
    sign,
)
from signedhook.django import SignedhookASGIMiddleware  # noqa: E402


def configure(**options: Any) -> None:
    if not dj_settings.configured:
        dj_settings.configure(DEBUG=True, ALLOWED_HOSTS=["*"], SIGNEDHOOK_ROUTES={})
    for name, value in options.items():
        setattr(dj_settings, name, value)


class FakeReceive:
    """Yields queued ASGI messages, then waits (disconnect) like a server."""

    def __init__(self, messages: list[dict[str, Any]]) -> None:
        self._messages = list(messages)
        self.calls = 0

    async def __call__(self) -> dict[str, Any]:
        self.calls += 1
        if self._messages:
            return self._messages.pop(0)
        return {"type": "http.disconnect"}


class SendRecorder:
    def __init__(self) -> None:
        self.messages: list[dict[str, Any]] = []

    async def __call__(self, message: dict[str, Any]) -> None:
        self.messages.append(message)


def chunk_messages(body: bytes, chunk_size: int) -> list[dict[str, Any]]:
    messages = [
        {"type": "http.request", "body": body[i : i + chunk_size], "more_body": True}
        for i in range(0, len(body), chunk_size)
    ]
    messages.append({"type": "http.request", "body": b"", "more_body": False})
    return messages


def make_scope(
    path: str = "/webhooks/std/", headers: dict[str, str] | None = None
) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "method": "POST",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [
            (name.lower().encode("latin-1"), value.encode("latin-1"))
            for name, value in (headers or {}).items()
        ],
    }


def make_wrapper(routes: dict[str, Any]) -> tuple[SignedhookASGIMiddleware, dict[str, Any]]:
    """Wrap a capturing inner ASGI app with the middleware."""
    captured: dict[str, Any] = {}

    async def inner_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        captured["called"] = True
        captured["scope"] = scope
        captured["receive"] = receive
        body = b""
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        captured["body"] = body
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"inner-ok"})

    configure(SIGNEDHOOK_ROUTES=routes)
    return SignedhookASGIMiddleware(inner_app), captured


def std_signed_headers(payload: bytes = PAYLOAD, webhook_id: str = "msg_asgi") -> dict[str, str]:
    return sign(payload, secret=STD_SECRET_HEADER, webhook_id=webhook_id)  # now=wall clock


def run(coro: Any) -> Any:
    return asyncio.run(coro)


STD_ROUTE = {"provider": "standard", "secrets": STD_SECRET_HEADER, "tolerance": 300}


class TestHappyPath:
    def test_verified_delivery_reaches_app_with_body_and_scope_result(self) -> None:
        wrapper, captured = make_wrapper({"/webhooks/std/": dict(STD_ROUTE)})
        receive = FakeReceive(chunk_messages(PAYLOAD, 16))
        send = SendRecorder()
        run(wrapper(make_scope(headers=std_signed_headers()), receive, send))

        assert captured["called"] is True
        assert captured["body"] == PAYLOAD
        result = captured["scope"]["signedhook"]
        assert result.provider == "standard"
        assert result.payload_size == len(PAYLOAD)
        # The app's own response passes through untouched.
        statuses = [m["status"] for m in send.messages if m["type"] == "http.response.start"]
        assert statuses == [200]
        bodies = [m["body"] for m in send.messages if m["type"] == "http.response.body"]
        assert bodies == [b"inner-ok"]

    def test_route_options_still_apply(self) -> None:
        # tolerance / max_payload_bytes are honoured on the ASGI path too.
        wrapper, _ = make_wrapper({"/webhooks/std/": {**STD_ROUTE, "max_payload_bytes": 256}})
        receive = FakeReceive(chunk_messages(b"x" * 300, 64))
        send = SendRecorder()
        run(wrapper(make_scope(headers=std_signed_headers(b"x" * 300)), receive, send))
        assert send.messages[0]["status"] == 413

    def test_stream_flag_is_irrelevant_here(self) -> None:
        # At the ASGI layer streaming is always used; the flag only governs
        # the Django middleware's WSGI behaviour.
        wrapper, captured = make_wrapper({"/webhooks/std/": {**STD_ROUTE, "stream": False}})
        receive = FakeReceive(chunk_messages(PAYLOAD, 16))
        send = SendRecorder()
        run(wrapper(make_scope(headers=std_signed_headers()), receive, send))
        assert captured["called"] is True
        assert captured["scope"]["signedhook"].provider == "standard"


class TestRejection:
    def test_tampered_delivery_never_reaches_app(self) -> None:
        wrapper, captured = make_wrapper({"/webhooks/std/": dict(STD_ROUTE)})
        messages = chunk_messages(PAYLOAD, 16)
        messages[0]["body"] = b"XXXX" + messages[0]["body"][4:]
        receive = FakeReceive(messages)
        send = SendRecorder()
        run(wrapper(make_scope(headers=std_signed_headers()), receive, send))

        assert "called" not in captured
        assert send.messages[0]["type"] == "http.response.start"
        assert send.messages[0]["status"] == 401
        error_body = json.loads(send.messages[-1]["body"])
        assert error_body["detail"]["code"] == "signature_mismatch"

    def test_stale_timestamp_rejected_without_reading_body(self) -> None:
        wrapper, captured = make_wrapper({"/webhooks/std/": dict(STD_ROUTE)})
        stale = sign(
            PAYLOAD, secret=STD_SECRET_HEADER, webhook_id="msg_stale", now=int(time.time()) - 10_000
        )
        receive = FakeReceive(chunk_messages(PAYLOAD, 16))
        send = SendRecorder()
        run(wrapper(make_scope(headers=stale), receive, send))

        assert receive.calls == 0  # not one body message pulled off the wire
        assert "called" not in captured
        assert send.messages[0]["status"] == 401
        error_body = json.loads(send.messages[-1]["body"])
        assert error_body["detail"]["code"] == "timestamp_outside_tolerance"

    def test_oversized_delivery_aborts_mid_stream(self) -> None:
        wrapper, captured = make_wrapper(
            {"/webhooks/std/": {**STD_ROUTE, "max_payload_bytes": 256}}
        )
        body = b"x" * 1000
        receive = FakeReceive(chunk_messages(body, 100))  # 10 chunks + final
        send = SendRecorder()
        run(wrapper(make_scope(headers=std_signed_headers(body)), receive, send))

        assert receive.calls == 3  # aborted on the chunk that crossed 256
        assert "called" not in captured
        assert send.messages[0]["status"] == 413
        error_body = json.loads(send.messages[-1]["body"])
        assert error_body["detail"]["code"] == "payload_too_large"

    def test_client_disconnect_mid_body_is_silent(self) -> None:
        wrapper, captured = make_wrapper({"/webhooks/std/": dict(STD_ROUTE)})
        receive = FakeReceive(
            [
                {"type": "http.request", "body": PAYLOAD[:8], "more_body": True},
                {"type": "http.disconnect"},
            ]
        )
        send = SendRecorder()
        run(wrapper(make_scope(headers=std_signed_headers()), receive, send))
        assert send.messages == []  # nothing to answer: the client is gone
        assert "called" not in captured


class TestReplay:
    def test_sync_cache_rejects_second_delivery(self) -> None:
        wrapper, _ = make_wrapper({"/webhooks/std/": {**STD_ROUTE, "replay": True}})
        for expected in (200, 409):
            receive = FakeReceive(chunk_messages(PAYLOAD, 16))
            send = SendRecorder()
            run(wrapper(make_scope(headers=std_signed_headers()), receive, send))
            assert send.messages[0]["status"] == expected

    def test_async_cache_is_awaited(self) -> None:
        wrapper, _ = make_wrapper(
            {"/webhooks/std/": {**STD_ROUTE, "replay_cache": AsyncMemoryReplayCache()}}
        )
        for expected in (200, 409):
            receive = FakeReceive(chunk_messages(PAYLOAD, 16))
            send = SendRecorder()
            run(wrapper(make_scope(headers=std_signed_headers()), receive, send))
            assert send.messages[0]["status"] == expected


class TestPassThrough:
    def test_non_matching_path_untouched(self) -> None:
        wrapper, captured = make_wrapper({"/webhooks/std/": dict(STD_ROUTE)})
        receive = FakeReceive(chunk_messages(b"unrelated", 16))
        send = SendRecorder()
        run(wrapper(make_scope(path="/api/other/"), receive, send))
        assert captured["called"] is True
        assert captured["receive"] is receive  # original receive channel

    def test_non_http_scope_untouched(self) -> None:
        wrapper, captured = make_wrapper({"/webhooks/std/": dict(STD_ROUTE)})

        async def ws_app(scope: dict[str, Any], receive: Any, send: Any) -> None:
            captured["called"] = True

        configure(SIGNEDHOOK_ROUTES={"/webhooks/std/": dict(STD_ROUTE)})
        wrapper.app = ws_app
        run(
            wrapper(
                {"type": "websocket", "path": "/webhooks/std/"}, FakeReceive([]), SendRecorder()
            )
        )
        assert captured["called"] is True


class TestFallbackAndMisconfiguration:
    def test_twilio_falls_back_to_buffered_error(self) -> None:
        wrapper, captured = make_wrapper({"/webhooks/tw/": {"provider": "twilio", "secrets": "t"}})
        receive = FakeReceive(chunk_messages(b"a=1", 16))
        send = SendRecorder()
        run(
            wrapper(
                make_scope(path="/webhooks/tw/", headers={"x-twilio-signature": "AAAA"}),
                receive,
                send,
            )
        )
        assert "called" not in captured
        assert send.messages[0]["status"] == 500
        error_body = json.loads(send.messages[-1]["body"])
        assert error_body["detail"]["code"] == "configuration_error"

    def test_twilio_fallback_enforces_size_cap_mid_stream(self) -> None:
        wrapper, captured = make_wrapper(
            {
                "/webhooks/tw/": {
                    "provider": "twilio",
                    "secrets": "t",
                    "max_payload_bytes": 256,
                }
            }
        )
        receive = FakeReceive(chunk_messages(b"x" * 1000, 100))
        send = SendRecorder()
        run(
            wrapper(
                make_scope(path="/webhooks/tw/", headers={"x-twilio-signature": "AAAA"}),
                receive,
                send,
            )
        )
        assert "called" not in captured
        assert send.messages[0]["status"] == 413
        assert receive.calls == 3

    def test_malformed_routes_report_500(self) -> None:
        wrapper, captured = make_wrapper({})
        configure(SIGNEDHOOK_ROUTES=["not", "a", "mapping"])
        receive = FakeReceive(chunk_messages(PAYLOAD, 16))
        send = SendRecorder()
        run(wrapper(make_scope(headers=std_signed_headers()), receive, send))
        assert "called" not in captured
        assert send.messages[0]["status"] == 500
        error_body = json.loads(send.messages[-1]["body"])
        assert error_body["detail"]["code"] == "configuration_error"
        configure(SIGNEDHOOK_ROUTES={})

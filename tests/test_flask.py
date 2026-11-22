"""Flask integration: decorator happy path, error mapping and replay."""

from __future__ import annotations

import io
import time

import pytest

flask = pytest.importorskip("flask")

from conftest import PAYLOAD, STD_SECRET_HEADER  # noqa: E402
from signedhook import MemoryReplayCache, Settings, sign  # noqa: E402
from signedhook.flask import verify_webhook  # noqa: E402


def fresh_std_headers(payload: bytes = PAYLOAD, webhook_id: str = "msg_1") -> dict[str, str]:
    """Standard Webhooks headers signed with the current time."""
    return sign(payload, secret=STD_SECRET_HEADER, webhook_id=webhook_id)


def make_app(**decorator_kwargs: object) -> flask.Flask:
    app = flask.Flask(__name__)

    @app.post("/hook")
    @verify_webhook(**decorator_kwargs)  # type: ignore[arg-type]
    def hook(result):  # noqa: ANN001
        return {"provider": result.provider, "size": result.payload_size}

    return app


@pytest.fixture()
def client() -> flask.testing.FlaskClient:
    return make_app(provider="standard", secrets=STD_SECRET_HEADER).test_client()


class TestHappyPath:
    def test_valid_signature_returns_200_with_result(
        self, client: flask.testing.FlaskClient
    ) -> None:
        response = client.post("/hook", data=PAYLOAD, headers=fresh_std_headers())
        assert response.status_code == 200
        assert response.get_json() == {"provider": "standard", "size": len(PAYLOAD)}

    def test_auto_detection(self) -> None:
        app = make_app(secrets=STD_SECRET_HEADER)
        with app.test_client() as auto_client:
            response = auto_client.post("/hook", data=PAYLOAD, headers=fresh_std_headers())
        assert response.status_code == 200
        assert response.get_json()["provider"] == "standard"

    def test_custom_result_kwarg(self) -> None:
        app = flask.Flask(__name__)

        @app.post("/hook")
        @verify_webhook(secrets=STD_SECRET_HEADER, result_kwarg="verification")
        def hook(verification):  # noqa: ANN001
            return {"provider": verification.provider}

        with app.test_client() as kwarg_client:
            response = kwarg_client.post("/hook", data=PAYLOAD, headers=fresh_std_headers())
        assert response.status_code == 200
        assert response.get_json() == {"provider": "standard"}

    def test_view_can_reread_the_body(self) -> None:
        app = flask.Flask(__name__)

        @app.post("/hook")
        @verify_webhook(secrets=STD_SECRET_HEADER)
        def hook(result):  # noqa: ANN001
            body = flask.request.get_data()
            return {"body_matches": body == PAYLOAD}

        with app.test_client() as reread_client:
            response = reread_client.post("/hook", data=PAYLOAD, headers=fresh_std_headers())
        assert response.status_code == 200
        assert response.get_json() == {"body_matches": True}


class TestErrorMapping:
    def test_bad_signature_is_401_with_code(self, client: flask.testing.FlaskClient) -> None:
        headers = fresh_std_headers()
        headers["webhook-signature"] = "v1,AAAA"
        response = client.post("/hook", data=PAYLOAD, headers=headers)
        assert response.status_code == 401
        assert response.get_json()["detail"]["code"] == "signature_mismatch"

    def test_missing_header_is_400_in_strict_mode(self) -> None:
        # Auto-detection cannot know which scheme was intended, so a partial
        # header set maps to 401 (unknown provider); strict mode produces the
        # precise 400 (missing header).
        app = make_app(provider="standard", secrets=STD_SECRET_HEADER)
        with app.test_client() as strict_client:
            response = strict_client.post("/hook", data=PAYLOAD, headers={"webhook-id": "msg_1"})
        assert response.status_code == 400
        assert response.get_json()["detail"]["code"] == "missing_header"

    def test_stale_timestamp_is_401(self, client: flask.testing.FlaskClient) -> None:
        stale = sign(
            PAYLOAD,
            secret=STD_SECRET_HEADER,
            webhook_id="msg_stale",
            now=int(time.time()) - 10_000,
        )
        response = client.post("/hook", data=PAYLOAD, headers=stale)
        assert response.status_code == 401
        assert response.get_json()["detail"]["code"] == "timestamp_outside_tolerance"

    def test_oversized_body_is_413(self) -> None:
        app = make_app(
            provider="standard",
            secrets=STD_SECRET_HEADER,
            settings=Settings(max_payload_bytes=300),
        )
        body = b"x" * 400
        headers = sign(body, secret=STD_SECRET_HEADER, webhook_id="msg_big")
        with app.test_client() as big_client:
            response = big_client.post("/hook", data=body, headers=headers)
        assert response.status_code == 413
        assert response.get_json()["detail"]["code"] == "payload_too_large"

    def test_misconfiguration_is_500(self) -> None:
        app = make_app(provider="standard", secrets="")
        with app.test_client() as broken_client:
            response = broken_client.post("/hook", data=PAYLOAD, headers=fresh_std_headers())
        assert response.status_code == 500
        assert response.get_json()["detail"]["code"] == "configuration_error"

    def test_error_messages_never_leak_secrets(self, client: flask.testing.FlaskClient) -> None:
        headers = fresh_std_headers()
        headers["webhook-signature"] = "v1,AAAA"
        response = client.post("/hook", data=PAYLOAD, headers=headers)
        assert STD_SECRET_HEADER not in response.get_data(as_text=True)


class TestReplay:
    def test_second_delivery_is_409(self) -> None:
        app = make_app(
            provider="standard",
            secrets=STD_SECRET_HEADER,
            replay_cache=MemoryReplayCache(),
        )
        headers = fresh_std_headers()
        with app.test_client() as replay_client:
            first = replay_client.post("/hook", data=PAYLOAD, headers=headers)
            second = replay_client.post("/hook", data=PAYLOAD, headers=headers)
        assert first.status_code == 200
        assert second.status_code == 409
        assert second.get_json()["detail"]["code"] == "replay_rejected"

    def test_replayed_unauthenticated_requests_do_not_consume_entries(self) -> None:
        app = make_app(
            provider="standard",
            secrets=STD_SECRET_HEADER,
            replay_cache=MemoryReplayCache(),
        )
        headers = fresh_std_headers()
        headers["webhook-signature"] = "v1,AAAA"
        with app.test_client() as attack_client:
            for _ in range(3):
                response = attack_client.post("/hook", data=PAYLOAD, headers=headers)
            assert response.status_code == 401
        # A subsequent genuine delivery must still be accepted (cache empty).
        with app.test_client() as good_client:
            response = good_client.post(
                "/hook", data=PAYLOAD, headers=fresh_std_headers(webhook_id="msg_good")
            )
        assert response.status_code == 200


class TestStreaming:
    """stream=True: incremental verification straight off the WSGI input."""

    def test_valid_signature_returns_200_with_result(self) -> None:
        app = make_app(provider="standard", secrets=STD_SECRET_HEADER, stream=True)
        with app.test_client() as stream_client:
            response = stream_client.post("/hook", data=PAYLOAD, headers=fresh_std_headers())
        assert response.status_code == 200
        assert response.get_json() == {"provider": "standard", "size": len(PAYLOAD)}

    def test_view_can_reread_body_after_streaming(self) -> None:
        app = flask.Flask(__name__)

        @app.post("/hook")
        @verify_webhook(secrets=STD_SECRET_HEADER, stream=True)
        def hook(result):  # noqa: ANN001
            raw = flask.request.get_data()
            parsed = flask.request.get_json()
            return {"raw_matches": raw == PAYLOAD, "parsed": parsed}

        with app.test_client() as reread_client:
            response = reread_client.post(
                "/hook",
                data=PAYLOAD,
                headers=fresh_std_headers(),
                content_type="application/json",
            )
        assert response.status_code == 200
        assert response.get_json() == {
            "raw_matches": True,
            "parsed": {"event": "ping", "seq": 1},
        }

    def test_view_can_parse_form_after_streaming(self) -> None:
        body = b"a=1&b=2"
        headers = sign(body, secret=STD_SECRET_HEADER, webhook_id="msg_form")
        app = flask.Flask(__name__)

        @app.post("/hook")
        @verify_webhook(secrets=STD_SECRET_HEADER, stream=True)
        def hook(result):  # noqa: ANN001
            return {"form": dict(flask.request.form), "size": result.payload_size}

        with app.test_client() as form_client:
            response = form_client.post(
                "/hook",
                data=body,
                headers=headers,
                content_type="application/x-www-form-urlencoded",
            )
        assert response.status_code == 200
        assert response.get_json() == {"form": {"a": "1", "b": "2"}, "size": len(body)}

    def test_bad_signature_is_401(self) -> None:
        app = make_app(provider="standard", secrets=STD_SECRET_HEADER, stream=True)
        headers = fresh_std_headers()
        headers["webhook-signature"] = "v1,AAAA"
        with app.test_client() as bad_client:
            response = bad_client.post("/hook", data=PAYLOAD, headers=headers)
        assert response.status_code == 401
        assert response.get_json()["detail"]["code"] == "signature_mismatch"

    def test_chunk_size_one_still_verifies(self) -> None:
        # Every byte is its own chunk: chunk-boundary equivalence.
        app = make_app(provider="standard", secrets=STD_SECRET_HEADER, stream=True, chunk_size=1)
        with app.test_client() as one_client:
            response = one_client.post("/hook", data=PAYLOAD, headers=fresh_std_headers())
        assert response.status_code == 200
        assert response.get_json()["size"] == len(PAYLOAD)

    def test_replay_is_409(self) -> None:
        app = make_app(
            provider="standard",
            secrets=STD_SECRET_HEADER,
            stream=True,
            replay_cache=MemoryReplayCache(),
        )
        headers = fresh_std_headers()
        with app.test_client() as replay_client:
            first = replay_client.post("/hook", data=PAYLOAD, headers=headers)
            second = replay_client.post("/hook", data=PAYLOAD, headers=headers)
        assert first.status_code == 200
        assert second.status_code == 409

    def test_twilio_falls_back_to_buffered_behaviour(self) -> None:
        for stream in (False, True):
            app = make_app(provider="twilio", secrets="token", stream=stream)
            with app.test_client() as twilio_client:
                response = twilio_client.post(
                    "/hook", data=b"a=1", headers={"x-twilio-signature": "AAAA"}
                )
            assert response.status_code == 500, stream
            assert response.get_json()["detail"]["code"] == "configuration_error"

    def test_twilio_fallback_enforces_size_cap(self) -> None:
        app = make_app(
            provider="twilio",
            secrets="token",
            stream=True,
            settings=Settings(max_payload_bytes=300),
        )
        body = b"x" * 400
        with app.test_client() as big_client:
            response = big_client.post("/hook", data=body, headers={"x-twilio-signature": "AAAA"})
        assert response.status_code == 413
        assert response.get_json()["detail"]["code"] == "payload_too_large"


class CountingInput:
    """WSGI input wrapper that counts reads, to observe mid-stream aborts."""

    def __init__(self, data: bytes) -> None:
        self._buffer = io.BytesIO(data)
        self.read_calls = 0
        self.bytes_read = 0

    def read(self, size: int = -1) -> bytes:
        self.read_calls += 1
        chunk = self._buffer.read(size)
        self.bytes_read += len(chunk)
        return chunk

    def readable(self) -> bool:
        return True


def call_wsgi(app: flask.Flask, body: bytes, headers: dict[str, str]):
    """Invoke the WSGI app directly with a counting input stream."""
    from werkzeug.test import EnvironBuilder

    builder = EnvironBuilder(method="POST", path="/hook", data=body, headers=headers)
    environ = builder.get_environ()
    counting = CountingInput(body)
    environ["wsgi.input"] = counting
    captured: dict[str, object] = {}

    def start_response(status, response_headers, exc_info=None):  # noqa: ANN001, ANN202
        captured["status"] = status

    rv = app(environ, start_response)
    data = b"".join(rv)
    if hasattr(rv, "close"):  # pragma: no cover - defensive
        rv.close()
    return int(str(captured["status"]).split()[0]), data, counting


class TestStreamingReads:
    """The stream stops reading exactly when verification fails."""

    def test_stale_timestamp_rejected_before_any_body_byte_is_read(self) -> None:
        app = make_app(provider="standard", secrets=STD_SECRET_HEADER, stream=True)
        stale = sign(
            PAYLOAD,
            secret=STD_SECRET_HEADER,
            webhook_id="msg_stale",
            now=int(time.time()) - 10_000,
        )
        status, _body, counting = call_wsgi(app, PAYLOAD, stale)
        assert status == 401
        assert counting.read_calls == 0
        assert counting.bytes_read == 0

    def test_oversized_body_aborts_mid_stream(self) -> None:
        app = make_app(
            provider="standard",
            secrets=STD_SECRET_HEADER,
            stream=True,
            chunk_size=100,
            settings=Settings(max_payload_bytes=256),
        )
        body = b"x" * 1000
        headers = sign(body, secret=STD_SECRET_HEADER, webhook_id="msg_big")
        status, body_out, counting = call_wsgi(app, body, headers)
        assert status == 413
        assert b"payload_too_large" in body_out
        # Only the chunks needed to cross the limit were pulled off the wire.
        assert counting.bytes_read == 300
        assert counting.read_calls == 3

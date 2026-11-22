"""Flask integration: decorator happy path, error mapping and replay."""

from __future__ import annotations

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

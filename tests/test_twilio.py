"""Twilio scheme tests."""

from __future__ import annotations

import urllib.parse

import pytest

from conftest import (
    TWILIO_PAIRS,
    TWILIO_PAIRS_SIG,
    TWILIO_PARAMS,
    TWILIO_SIG,
    TWILIO_TOKEN,
    TWILIO_URL,
    hmac_sha1_b64,
)
from signedhook import (
    ConfigurationError,
    InvalidHeaderFormatError,
    MemoryReplayCache,
    MissingHeaderError,
    ReplayRejectedError,
    SignatureMismatchError,
    sign_twilio,
    verify,
    verify_twilio,
)
from signedhook.twilio import twilio_string_to_sign


def tw_headers(sig: str = TWILIO_SIG) -> dict[str, str]:
    return {"X-Twilio-Signature": sig}


def test_accepts_independently_computed_vector() -> None:
    result = verify_twilio(TWILIO_URL, TWILIO_PARAMS, tw_headers(), secrets=TWILIO_TOKEN)
    assert result.provider == "twilio"
    assert result.scheme == "hmac-sha1"
    assert result.timestamp is None
    assert result.matched_secret_index == 0
    assert result.message_key is None


def test_accepts_duplicate_key_pairs() -> None:
    result = verify_twilio(
        TWILIO_URL, TWILIO_PAIRS, tw_headers(TWILIO_PAIRS_SIG), secrets=TWILIO_TOKEN
    )
    assert result.provider == "twilio"


def test_string_to_sign_sorts_and_concatenates() -> None:
    expected = (
        TWILIO_URL
        + "AccountSidACeeeeeeeeeeeeeeeeeeeeeeeeeeeeCallStatuscompletedCalled+14155551234From+14157779999"
    )
    assert twilio_string_to_sign(TWILIO_URL, TWILIO_PARAMS) == expected


def test_string_to_sign_sorts_duplicate_pairs_by_key_then_value() -> None:
    assert (
        twilio_string_to_sign("https://h", [("b", "2"), ("a", "1"), ("b", "1")])
        == "https://ha1b1b2"
    )


def test_rejects_tampered_params() -> None:
    tampered = dict(TWILIO_PARAMS)
    tampered["CallStatus"] = "in-progress"
    with pytest.raises(SignatureMismatchError):
        verify_twilio(TWILIO_URL, tampered, tw_headers(), secrets=TWILIO_TOKEN)


def test_rejects_wrong_url() -> None:
    with pytest.raises(SignatureMismatchError):
        verify_twilio(TWILIO_URL + "x", TWILIO_PARAMS, tw_headers(), secrets=TWILIO_TOKEN)


def test_rotation_matches_second_secret() -> None:
    old_token = "ffffffffffffffffffffffffffffffff"
    content = twilio_string_to_sign(TWILIO_URL, TWILIO_PARAMS).encode("utf-8")
    sig = hmac_sha1_b64(old_token, content)
    result = verify_twilio(
        TWILIO_URL, TWILIO_PARAMS, tw_headers(sig), secrets=[TWILIO_TOKEN, old_token]
    )
    assert result.matched_secret_index == 1


def test_missing_header_reported() -> None:
    with pytest.raises(MissingHeaderError) as excinfo:
        verify_twilio(TWILIO_URL, TWILIO_PARAMS, {}, secrets=TWILIO_TOKEN)
    assert excinfo.value.header == "x-twilio-signature"


def test_invalid_base64_rejected() -> None:
    with pytest.raises(InvalidHeaderFormatError):
        verify_twilio(TWILIO_URL, TWILIO_PARAMS, tw_headers("!!not-base64!!"), secrets=TWILIO_TOKEN)


def test_header_matched_case_insensitively() -> None:
    result = verify_twilio(
        TWILIO_URL, TWILIO_PARAMS, {"x-TWILIO-SIGNATURE": TWILIO_SIG}, secrets=TWILIO_TOKEN
    )
    assert result.provider == "twilio"


def test_payload_size_is_form_encoded_length() -> None:
    result = verify_twilio(TWILIO_URL, TWILIO_PARAMS, tw_headers(), secrets=TWILIO_TOKEN)
    expected = len(urllib.parse.urlencode(sorted(TWILIO_PARAMS.items())).encode("utf-8"))
    assert result.payload_size == expected


def test_empty_url_rejected() -> None:
    with pytest.raises(ConfigurationError):
        verify_twilio("", TWILIO_PARAMS, tw_headers(), secrets=TWILIO_TOKEN)


def test_non_string_url_rejected() -> None:
    with pytest.raises(TypeError):
        verify_twilio(1234, TWILIO_PARAMS, tw_headers(), secrets=TWILIO_TOKEN)  # type: ignore[arg-type]


def test_non_string_param_values_rejected() -> None:
    with pytest.raises(TypeError):
        verify_twilio(TWILIO_URL, [("a", 1)], tw_headers(), secrets=TWILIO_TOKEN)  # type: ignore[list-item]


class TestReplay:
    def test_duplicate_delivery_rejected(self) -> None:
        cache = MemoryReplayCache()
        first = verify_twilio(
            TWILIO_URL, TWILIO_PARAMS, tw_headers(), secrets=TWILIO_TOKEN, replay_cache=cache
        )
        assert first.provider == "twilio"
        with pytest.raises(ReplayRejectedError):
            verify_twilio(
                TWILIO_URL, TWILIO_PARAMS, tw_headers(), secrets=TWILIO_TOKEN, replay_cache=cache
            )

    def test_unauthenticated_traffic_cannot_poison_cache(self) -> None:
        cache = MemoryReplayCache()
        with pytest.raises(SignatureMismatchError):
            verify_twilio(
                TWILIO_URL,
                TWILIO_PARAMS,
                tw_headers("AAAA" + TWILIO_SIG[4:]),
                secrets=TWILIO_TOKEN,
                replay_cache=cache,
            )
        assert len(cache) == 0

    def test_explicit_key(self) -> None:
        cache = MemoryReplayCache()
        verify_twilio(
            TWILIO_URL,
            TWILIO_PARAMS,
            tw_headers(),
            secrets=TWILIO_TOKEN,
            replay_cache=cache,
            key="my-dedupe-key",
        )
        with pytest.raises(ReplayRejectedError) as excinfo:
            verify_twilio(
                TWILIO_URL,
                TWILIO_PARAMS,
                tw_headers(),
                secrets=TWILIO_TOKEN,
                replay_cache=cache,
                key="my-dedupe-key",
            )
        assert excinfo.value.key_id == "my-dedupe-key"

    def test_different_content_not_rejected(self) -> None:
        cache = MemoryReplayCache()
        verify_twilio(
            TWILIO_URL, TWILIO_PARAMS, tw_headers(), secrets=TWILIO_TOKEN, replay_cache=cache
        )
        other_params = dict(TWILIO_PARAMS)
        other_params["CallStatus"] = "ringing"
        content = twilio_string_to_sign(TWILIO_URL, other_params).encode("utf-8")
        result = verify_twilio(
            TWILIO_URL,
            other_params,
            tw_headers(hmac_sha1_b64(TWILIO_TOKEN, content)),
            secrets=TWILIO_TOKEN,
            replay_cache=cache,
        )
        assert result.provider == "twilio"


class TestSigning:
    def test_matches_independent_vector(self) -> None:
        headers = sign_twilio(TWILIO_URL, TWILIO_PARAMS, secret=TWILIO_TOKEN)
        assert headers == {"x-twilio-signature": TWILIO_SIG}

    def test_round_trip(self) -> None:
        url = "https://app.example.com/sms/status?beta=true"
        params = {"MessageSid": "SMeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "MessageStatus": "sent"}
        headers = sign_twilio(url, params, secret=TWILIO_TOKEN)
        result = verify_twilio(url, params, headers, secrets=TWILIO_TOKEN)
        assert result.provider == "twilio"


class TestRegistryStub:
    def test_strict_provider_raises_actionable_error(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            verify(b"{}", tw_headers(), secrets=TWILIO_TOKEN, provider="twilio")
        assert "verify_twilio" in str(excinfo.value)

    def test_auto_detection_raises_actionable_error(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            verify(b"{}", tw_headers(), secrets=TWILIO_TOKEN)
        assert "verify_twilio" in str(excinfo.value)

    def test_twilio_listed_in_registry(self) -> None:
        from signedhook import list_providers

        assert "twilio" in list_providers()

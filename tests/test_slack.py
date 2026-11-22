"""Slack scheme tests."""

from __future__ import annotations

import pytest

from conftest import NOW, PAYLOAD, SLACK_SECRET, SLACK_SIG, hmac_sha256_hex
from signedhook import (
    InvalidHeaderFormatError,
    MissingHeaderError,
    SignatureMismatchError,
    TimestampToleranceExceededError,
    verify,
)


def slack_headers(sig: str = SLACK_SIG, ts: int = NOW) -> dict[str, str]:
    return {"x-slack-signature": sig, "x-slack-request-timestamp": str(ts)}


def signed_for(ts: int, secret: str = SLACK_SECRET, payload: bytes = PAYLOAD) -> str:
    return "v0=" + hmac_sha256_hex(secret, b"v0:" + str(ts).encode() + b":" + payload)


def test_accepts_independently_computed_vector() -> None:
    result = verify(PAYLOAD, slack_headers(), secrets=SLACK_SECRET, provider="slack", now=NOW)
    assert result.provider == "slack"
    assert result.timestamp == NOW


def test_rejects_tampered_payload() -> None:
    with pytest.raises(SignatureMismatchError):
        verify(b'{"other":true}', slack_headers(), secrets=SLACK_SECRET, provider="slack", now=NOW)


def test_tolerance_window_applies() -> None:
    with pytest.raises(TimestampToleranceExceededError):
        verify(PAYLOAD, slack_headers(), secrets=SLACK_SECRET, provider="slack", now=NOW + 301)


def test_shifted_timestamp_changes_signed_content() -> None:
    ts = NOW + 10
    with pytest.raises(SignatureMismatchError):
        verify(
            PAYLOAD,
            slack_headers(ts=ts),  # signature still for NOW
            secrets=SLACK_SECRET,
            provider="slack",
            now=ts,
        )


def test_missing_timestamp_header_reported() -> None:
    headers = {"x-slack-signature": SLACK_SIG}
    with pytest.raises(MissingHeaderError) as excinfo:
        verify(PAYLOAD, headers, secrets=SLACK_SECRET, provider="slack", now=NOW)
    assert excinfo.value.header == "x-slack-request-timestamp"


def test_wrong_version_prefix_rejected() -> None:
    sig = "v1=" + hmac_sha256_hex(SLACK_SECRET, b"v1:x:" + PAYLOAD)
    with pytest.raises(InvalidHeaderFormatError):
        verify(PAYLOAD, slack_headers(sig=sig), secrets=SLACK_SECRET, provider="slack", now=NOW)


def test_dynamic_signature_roundtrip() -> None:
    ts = NOW - 60
    headers = slack_headers(sig=signed_for(ts), ts=ts)
    result = verify(PAYLOAD, headers, secrets=SLACK_SECRET, provider="slack", now=NOW)
    assert result.provider == "slack"

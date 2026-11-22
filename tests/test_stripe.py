"""Stripe scheme tests: canonical vector, tolerance, header parsing rules."""

from __future__ import annotations

import pytest

from conftest import NOW, PAYLOAD, STRIPE_SECRET, hmac_sha256_hex, stripe_headers
from signedhook import (
    InvalidHeaderFormatError,
    SignatureMismatchError,
    TimestampToleranceExceededError,
    verify,
)


class TestCanonicalVector:
    def test_accepts_independently_computed_vector(self) -> None:
        result = verify(
            PAYLOAD, stripe_headers(), secrets=STRIPE_SECRET, provider="stripe", now=NOW
        )
        assert result.provider == "stripe"
        assert result.timestamp == NOW
        assert result.message_key is None

    def test_rejects_tampered_payload(self) -> None:
        with pytest.raises(SignatureMismatchError):
            verify(
                b'{"event":"ping","seq":2}',
                stripe_headers(),
                secrets=STRIPE_SECRET,
                provider="stripe",
                now=NOW,
            )

    def test_secret_without_prefix_is_accepted(self) -> None:
        result = verify(
            PAYLOAD,
            stripe_headers(),
            secrets="test_stripe_secret_key_0001",
            provider="stripe",
            now=NOW,
        )
        assert result.provider == "stripe"


class TestTolerance:
    def test_rejects_beyond_window(self) -> None:
        with pytest.raises(TimestampToleranceExceededError):
            verify(
                PAYLOAD, stripe_headers(), secrets=STRIPE_SECRET, provider="stripe", now=NOW + 301
            )

    def test_accepts_window_edge(self) -> None:
        result = verify(
            PAYLOAD, stripe_headers(), secrets=STRIPE_SECRET, provider="stripe", now=NOW + 300
        )
        assert result.provider == "stripe"

    def test_explicit_none_disables_check(self) -> None:
        result = verify(
            PAYLOAD,
            stripe_headers(),
            secrets=STRIPE_SECRET,
            provider="stripe",
            now=NOW + 99999,
            tolerance=None,
        )
        assert result.provider == "stripe"

    def test_future_timestamps_rejected_symmetrically(self) -> None:
        sig = (
            "t="
            + str(NOW + 5000)
            + ",v1="
            + hmac_sha256_hex(
                "test_stripe_secret_key_0001", str(NOW + 5000).encode() + b"." + PAYLOAD
            )
        )
        with pytest.raises(TimestampToleranceExceededError):
            verify(
                PAYLOAD,
                stripe_headers(sig=sig),
                secrets=STRIPE_SECRET,
                provider="stripe",
                now=NOW,
            )


class TestHeaderParsing:
    def test_multiple_v1_components_all_considered(self) -> None:
        alt_key = "whsec_rotated_stripe_key_000000001"
        alt_sig = hmac_sha256_hex(
            alt_key.removeprefix("whsec_"), str(NOW).encode() + b"." + PAYLOAD
        )
        canonical = hmac_sha256_hex(
            STRIPE_SECRET.removeprefix("whsec_"), str(NOW).encode() + b"." + PAYLOAD
        )
        headers = stripe_headers(f"t={NOW},v1={canonical},v1={alt_sig}")
        result = verify(PAYLOAD, headers, secrets=alt_key, provider="stripe", now=NOW)
        assert result.provider == "stripe"

    def test_missing_t_component_rejected(self) -> None:
        sig = "v1=" + hmac_sha256_hex(
            "test_stripe_secret_key_0001", str(NOW).encode() + b"." + PAYLOAD
        )
        with pytest.raises(InvalidHeaderFormatError) as excinfo:
            verify(PAYLOAD, stripe_headers(sig), secrets=STRIPE_SECRET, provider="stripe", now=NOW)
        assert "t=" in str(excinfo.value)

    def test_component_without_equals_rejected(self) -> None:
        with pytest.raises(InvalidHeaderFormatError):
            verify(
                PAYLOAD,
                stripe_headers("t=1700000000,garbage,v1=abc"),
                secrets=STRIPE_SECRET,
                provider="stripe",
                now=NOW,
            )

    def test_duplicate_timestamp_rejected(self) -> None:
        with pytest.raises(InvalidHeaderFormatError):
            verify(
                PAYLOAD,
                stripe_headers(f"t={NOW},t={NOW},v1=abc"),
                secrets=STRIPE_SECRET,
                provider="stripe",
                now=NOW,
            )

    def test_missing_v1_component_rejected(self) -> None:
        with pytest.raises(InvalidHeaderFormatError) as excinfo:
            verify(
                PAYLOAD,
                stripe_headers(f"t={NOW}"),
                secrets=STRIPE_SECRET,
                provider="stripe",
                now=NOW,
            )
        assert "v1=" in str(excinfo.value)

    def test_unknown_components_are_ignored(self) -> None:
        real = hmac_sha256_hex("test_stripe_secret_key_0001", str(NOW).encode() + b"." + PAYLOAD)
        headers = stripe_headers(f"t={NOW},platform=webhooks,v1={real}")
        result = verify(PAYLOAD, headers, secrets=STRIPE_SECRET, provider="stripe", now=NOW)
        assert result.provider == "stripe"

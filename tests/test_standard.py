"""Standard Webhooks / Svix scheme tests, anchored on an independently
computed canonical vector plus dynamic recomputation."""

from __future__ import annotations

import base64

import pytest

from conftest import (
    NOW,
    PAYLOAD,
    STD_ID,
    STD_RAW_KEY,
    STD_SECRET_HEADER,
    STD_SIG,
    hmac_sha256_b64,
    std_headers,
)
from signedhook import (
    ConfigurationError,
    InvalidHeaderFormatError,
    MissingHeaderError,
    SignatureMismatchError,
    TimestampToleranceExceededError,
    sign,
    verify,
)


class TestCanonicalVector:
    def test_accepts_independently_computed_vector(self) -> None:
        result = verify(
            PAYLOAD, std_headers(), secrets=STD_SECRET_HEADER, provider="standard", now=NOW
        )
        assert result.provider == "standard"
        assert result.scheme == "hmac-sha256"
        assert result.timestamp == NOW
        assert result.message_key == STD_ID
        assert result.matched_secret_index == 0
        assert result.payload_size == len(PAYLOAD)

    def test_accepts_raw_secret_fallback(self) -> None:
        secret = "raw-secret-with-dashes!"
        content = f"{STD_ID}.{NOW}.".encode() + PAYLOAD
        sig = "v1," + hmac_sha256_b64(secret, content)
        result = verify(PAYLOAD, std_headers(sig=sig), secrets=secret, provider="standard", now=NOW)
        assert result.provider == "standard"

    def test_rejects_tampered_payload(self) -> None:
        with pytest.raises(SignatureMismatchError) as excinfo:
            verify(
                PAYLOAD + b" ",
                std_headers(),
                secrets=STD_SECRET_HEADER,
                provider="standard",
                now=NOW,
            )
        assert excinfo.value.code == "signature_mismatch"

    def test_rejects_tampered_webhook_id(self) -> None:
        with pytest.raises(SignatureMismatchError):
            verify(
                PAYLOAD,
                std_headers(webhook_id="msg_other"),
                secrets=STD_SECRET_HEADER,
                provider="standard",
                now=NOW,
            )

    def test_rejects_shifted_timestamp_even_within_tolerance(self) -> None:
        # Changing the timestamp header changes the signed content.
        with pytest.raises(SignatureMismatchError):
            verify(
                PAYLOAD,
                std_headers(ts=NOW + 10),
                secrets=STD_SECRET_HEADER,
                provider="standard",
                now=NOW + 10,
            )


class TestTolerance:
    @pytest.mark.parametrize("delta", [-301, 301])
    def test_rejects_beyond_symmetric_window(self, delta: int) -> None:
        with pytest.raises(TimestampToleranceExceededError) as excinfo:
            verify(
                PAYLOAD,
                std_headers(),
                secrets=STD_SECRET_HEADER,
                provider="standard",
                now=NOW + delta,
            )
        assert excinfo.value.code == "timestamp_outside_tolerance"
        assert excinfo.value.limit_seconds == 300

    @pytest.mark.parametrize("delta", [-300, 0, 300])
    def test_accepts_window_edges(self, delta: int) -> None:
        result = verify(
            PAYLOAD,
            std_headers(),
            secrets=STD_SECRET_HEADER,
            provider="standard",
            now=NOW + delta,
        )
        assert result.provider == "standard"


class TestHeaders:
    @pytest.mark.parametrize("header", ["webhook-id", "webhook-timestamp", "webhook-signature"])
    def test_missing_header_is_reported_precisely(self, header: str) -> None:
        headers = std_headers()
        del headers[header]
        with pytest.raises(MissingHeaderError) as excinfo:
            verify(PAYLOAD, headers, secrets=STD_SECRET_HEADER, provider="standard", now=NOW)
        assert excinfo.value.header == header

    def test_malformed_signature_reports_invalid_format(self) -> None:
        with pytest.raises(InvalidHeaderFormatError):
            verify(
                PAYLOAD,
                std_headers(sig="v1,!!!not-base64!!!"),
                secrets=STD_SECRET_HEADER,
                provider="standard",
                now=NOW,
            )

    def test_blank_signature_header_reports_no_signatures(self) -> None:
        with pytest.raises(InvalidHeaderFormatError) as excinfo:
            verify(
                PAYLOAD,
                std_headers(sig="   "),
                secrets=STD_SECRET_HEADER,
                provider="standard",
                now=NOW,
            )
        assert "no signatures" in str(excinfo.value)

    def test_non_digit_timestamp_rejected(self) -> None:
        headers = std_headers()
        headers["webhook-timestamp"] = "yesterday"
        with pytest.raises(InvalidHeaderFormatError):
            verify(PAYLOAD, headers, secrets=STD_SECRET_HEADER, provider="standard", now=NOW)

    def test_uppercase_header_names_are_normalised(self) -> None:
        headers = {k.upper(): v for k, v in std_headers().items()}
        result = verify(PAYLOAD, headers, secrets=STD_SECRET_HEADER, provider="standard", now=NOW)
        assert result.provider == "standard"


class TestRotation:
    def test_multi_signature_header_rotates_across_secrets(self) -> None:
        alt_secret_raw = b"rotated-key-0000000000000000000000"
        alt_secret = "whsec_" + base64.b64encode(alt_secret_raw).decode()
        content = f"{STD_ID}.{NOW}.".encode() + PAYLOAD
        alt_sig = "v1," + hmac_sha256_b64(alt_secret_raw, content)
        headers = std_headers(sig=f"{STD_SIG} {alt_sig}")
        result = verify(PAYLOAD, headers, secrets=STD_SECRET_HEADER, provider="standard", now=NOW)
        assert result.matched_secret_index == 0
        result_alt = verify(PAYLOAD, headers, secrets=alt_secret, provider="standard", now=NOW)
        assert result_alt.matched_secret_index == 0

    def test_unprefixed_entry_is_accepted(self) -> None:
        bare = STD_SIG[len("v1,") :]
        headers = std_headers(sig=f"{STD_SIG} {bare}")
        result = verify(PAYLOAD, headers, secrets=STD_SECRET_HEADER, provider="standard", now=NOW)
        assert result.provider == "standard"

    def test_whsec_prefix_is_stripped(self) -> None:
        result = verify(
            PAYLOAD,
            std_headers(),
            secrets=STD_SECRET_HEADER,
            provider="standard",
            now=NOW,
        )
        assert result.provider == "standard"


class TestSignRoundTrip:
    def test_sign_then_verify(self) -> None:
        headers = sign(PAYLOAD, secret=STD_SECRET_HEADER, webhook_id="msg_rt_1", now=NOW)
        result = verify(PAYLOAD, headers, secrets=STD_SECRET_HEADER, provider="auto", now=NOW)
        assert result.provider == "standard"
        assert result.message_key == "msg_rt_1"

    def test_sign_rejects_unknown_scheme(self) -> None:
        with pytest.raises(ConfigurationError):
            sign(PAYLOAD, secret=STD_SECRET_HEADER, webhook_id="x", scheme="acme")

    def test_sign_rejects_str_payload(self) -> None:
        with pytest.raises(TypeError):
            sign('{"a":1}', secret=STD_SECRET_HEADER, webhook_id="x")  # type: ignore[arg-type]

    def test_sign_rejects_empty_id(self) -> None:
        with pytest.raises(ConfigurationError):
            sign(PAYLOAD, secret=STD_SECRET_HEADER, webhook_id="")

    def test_sign_output_has_no_secret_material(self) -> None:
        headers = sign(PAYLOAD, secret=STD_SECRET_HEADER, webhook_id="msg_rt_2", now=NOW)
        blob = repr(headers)
        assert STD_SECRET_HEADER not in blob
        assert "whsec_" not in blob


def test_raw_key_matches_vector_key() -> None:
    """The canonical header decodes to the documented raw key."""
    assert base64.b64decode(STD_SECRET_HEADER.removeprefix("whsec_")) == STD_RAW_KEY

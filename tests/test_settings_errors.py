"""Settings validation and error-contract tests (stable codes, safe messages)."""

from __future__ import annotations

import pytest

from conftest import NOW, STD_SECRET_HEADER, std_headers
from signedhook import (
    ConfigurationError,
    InvalidHeaderFormatError,
    MemoryReplayCache,
    MissingHeaderError,
    PayloadTooLargeError,
    ReplayRejectedError,
    Settings,
    SignatureMismatchError,
    SignedhookError,
    TimestampToleranceExceededError,
    UnknownProviderError,
    verify_with_replay,
)


class TestSettings:
    @pytest.mark.parametrize("value", [0, -5, 86401])
    def test_invalid_tolerance_rejected(self, value: int) -> None:
        with pytest.raises(ConfigurationError):
            Settings(tolerance_seconds=value)

    def test_none_tolerance_allowed(self) -> None:
        assert Settings(tolerance_seconds=None).tolerance_seconds is None

    @pytest.mark.parametrize("value", [100, 65 * 1024 * 1024])
    def test_invalid_max_payload_rejected(self, value: int) -> None:
        with pytest.raises(ConfigurationError):
            Settings(max_payload_bytes=value)

    def test_env_invalid_int_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VERIHOOK_TOLERANCE_SECONDS", "soon")
        with pytest.raises(ConfigurationError):
            Settings.from_env()

    def test_env_invalid_payload_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VERIHOOK_MAX_PAYLOAD_BYTES", "lots")
        with pytest.raises(ConfigurationError):
            Settings.from_env()

    def test_env_unset_yields_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("VERIHOOK_TOLERANCE_SECONDS", raising=False)
        monkeypatch.delenv("VERIHOOK_MAX_PAYLOAD_BYTES", raising=False)
        settings = Settings.from_env()
        assert settings.tolerance_seconds == 300
        assert settings.max_payload_bytes == 2 * 1024 * 1024


class TestErrorContract:
    @pytest.mark.parametrize(
        "error,code",
        [
            (ConfigurationError("x"), "configuration_error"),
            (PayloadTooLargeError(10, 5), "payload_too_large"),
            (MissingHeaderError("h"), "missing_header"),
            (InvalidHeaderFormatError("h", "bad"), "invalid_header_format"),
            (TimestampToleranceExceededError(10, 5), "timestamp_outside_tolerance"),
            (SignatureMismatchError("stripe"), "signature_mismatch"),
            (UnknownProviderError("x"), "unknown_provider"),
            (ReplayRejectedError("k"), "replay_rejected"),
        ],
    )
    def test_stable_codes(self, error: SignedhookError, code: str) -> None:
        assert error.code == code

    def test_mismatch_message_contains_no_secret(self) -> None:
        secret = STD_SECRET_HEADER
        error = SignatureMismatchError("standard")
        assert secret not in str(error)

    def test_payload_too_large_attributes(self) -> None:
        error = PayloadTooLargeError(size=600, limit=512)
        assert error.size == 600
        assert error.limit == 512

    def test_tolerance_error_attributes(self) -> None:
        error = TimestampToleranceExceededError(delta_seconds=400, limit_seconds=300)
        assert error.delta_seconds == 400
        assert error.limit_seconds == 300

    def test_missing_header_attribute(self) -> None:
        assert MissingHeaderError("webhook-id").header == "webhook-id"

    def test_replay_key_truncated_in_message(self) -> None:
        error = ReplayRejectedError("k" * 200)
        assert len(error.key_id) == 64

    def test_verify_failures_are_signedhook_errors(self) -> None:
        cache = MemoryReplayCache()
        with pytest.raises(SignedhookError) as excinfo:
            verify_with_replay(
                b"tampered-payload",
                std_headers(),
                cache,
                secrets=STD_SECRET_HEADER,
                provider="standard",
                now=NOW,
            )
        assert excinfo.value.code == "signature_mismatch"

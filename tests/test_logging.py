"""Structured logging behaviour and secret-hygiene guarantees."""

from __future__ import annotations

import logging

import pytest

from conftest import NOW, PAYLOAD, STD_SECRET_HEADER, std_headers
from signedhook import SignatureMismatchError, verify


def test_success_log_carries_structured_fields(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="signedhook.verify"):
        verify(PAYLOAD, std_headers(), secrets=STD_SECRET_HEADER, provider="standard", now=NOW)
    record = next(r for r in caplog.records if r.outcome == "success")
    assert record.provider == "standard"
    assert record.reason_code == ""


def test_failure_log_carries_reason_code(caplog: pytest.LogCaptureFixture) -> None:
    with (
        caplog.at_level(logging.DEBUG, logger="signedhook.verify"),
        pytest.raises(SignatureMismatchError),
    ):
        verify(
            b"tampered",
            std_headers(),
            secrets=STD_SECRET_HEADER,
            provider="standard",
            now=NOW,
        )
    record = next(r for r in caplog.records if r.outcome == "failure")
    assert record.reason_code == "signature_mismatch"


def test_logs_never_contain_secret_material(caplog: pytest.LogCaptureFixture) -> None:
    with (
        caplog.at_level(logging.DEBUG, logger="signedhook.verify"),
        pytest.raises(SignatureMismatchError),
    ):
        verify(
            b"tampered",
            std_headers(),
            secrets=STD_SECRET_HEADER,
            provider="standard",
            now=NOW,
        )
    verify(PAYLOAD, std_headers(), secrets=STD_SECRET_HEADER, provider="standard", now=NOW)
    blob = caplog.text
    assert STD_SECRET_HEADER not in blob
    assert "whsec_" not in blob
    assert PAYLOAD.decode() not in blob

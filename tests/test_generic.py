"""GenericHMAC configuration and verification tests."""

from __future__ import annotations

import pytest

from conftest import NOW, PAYLOAD, hmac_sha256_b64, hmac_sha256_hex
from signedhook import (
    ConfigurationError,
    GenericHMAC,
    MissingHeaderError,
    SignatureMismatchError,
    TimestampToleranceExceededError,
    register_provider,
    verify,
)
from signedhook._providers import _REGISTRY


@pytest.fixture()
def acme() -> GenericHMAC:
    provider = GenericHMAC(
        name="acme-test",
        sig_header="x-acme-signature",
        sig_prefix="sha256=",
        ts_header="x-acme-timestamp",
        signed_template="{ts}.{payload}",
        encoding="hex",
    )
    register_provider(provider, replace=True)
    yield provider
    _REGISTRY.pop("acme-test", None)


ACME_SECRET = "acme-webhook-secret-0000000001"


def _acme_headers(ts: int, payload: bytes, secret: str = ACME_SECRET) -> dict[str, str]:
    sig = "sha256=" + hmac_sha256_hex(secret, str(ts).encode() + b"." + payload)
    return {"x-acme-signature": sig, "x-acme-timestamp": str(ts)}


def test_configured_scheme_verifies(acme: GenericHMAC) -> None:
    result = verify(
        PAYLOAD, _acme_headers(NOW, PAYLOAD), secrets=ACME_SECRET, provider="acme-test", now=NOW
    )
    assert result.provider == "acme-test"


def test_configured_scheme_auto_detects(acme: GenericHMAC) -> None:
    result = verify(
        PAYLOAD, _acme_headers(NOW, PAYLOAD), secrets=ACME_SECRET, provider="auto", now=NOW
    )
    assert result.provider == "acme-test"


def test_configured_scheme_tolerates_window(acme: GenericHMAC) -> None:
    with pytest.raises(TimestampToleranceExceededError):
        verify(
            PAYLOAD,
            _acme_headers(NOW, PAYLOAD),
            secrets=ACME_SECRET,
            provider="acme-test",
            now=NOW + 301,
        )


def test_template_without_timestamp() -> None:
    provider = GenericHMAC(
        name="acme-plain",
        sig_header="x-acme-signature",
        encoding="hex",
        signed_template="{payload}",
    )
    register_provider(provider, replace=True)
    try:
        sig = hmac_sha256_hex(ACME_SECRET, PAYLOAD)
        result = verify(
            PAYLOAD,
            {"x-acme-signature": sig},
            secrets=ACME_SECRET,
            provider="acme-plain",
            now=NOW,
        )
        assert result.timestamp is None
    finally:
        _REGISTRY.pop("acme-plain", None)


def test_base64_encoding_and_secret_prefix() -> None:
    provider = GenericHMAC(
        name="acme-b64",
        sig_header="x-acme-signature",
        encoding="base64",
        secret_prefix="whsec_",
        base64_secrets=False,
        signed_template="{payload}",
    )
    register_provider(provider, replace=True)
    try:
        secret = "whsec_" + ACME_SECRET
        sig = hmac_sha256_b64(ACME_SECRET, PAYLOAD)
        result = verify(
            PAYLOAD,
            {"x-acme-signature": sig},
            secrets=secret,
            provider="acme-b64",
        )
        assert result.provider == "acme-b64"
    finally:
        _REGISTRY.pop("acme-b64", None)


def test_message_key_header_surfaces_key() -> None:
    provider = GenericHMAC(
        name="acme-keyed",
        sig_header="x-acme-signature",
        signed_template="{payload}",
        message_key_header="x-acme-event-id",
    )
    register_provider(provider, replace=True)
    try:
        sig = hmac_sha256_hex(ACME_SECRET, PAYLOAD)
        result = verify(
            PAYLOAD,
            {"x-acme-signature": sig, "x-acme-event-id": "evt_42"},
            secrets=ACME_SECRET,
            provider="acme-keyed",
        )
        assert result.message_key == "evt_42"
    finally:
        _REGISTRY.pop("acme-keyed", None)


def test_missing_timestamp_header_reported(acme: GenericHMAC) -> None:
    with pytest.raises(MissingHeaderError):
        verify(
            PAYLOAD,
            {"x-acme-signature": "sha256=" + "ab" * 8},
            secrets=ACME_SECRET,
            provider="acme-test",
            now=NOW,
        )


def test_wrong_signature_rejected(acme: GenericHMAC) -> None:
    with pytest.raises(SignatureMismatchError):
        verify(
            PAYLOAD,
            _acme_headers(NOW, PAYLOAD, secret="different-secret-0000000000000001"),
            secrets=ACME_SECRET,
            provider="acme-test",
            now=NOW,
        )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"name": "", "sig_header": "x-sig"},
        {"name": "ok", "sig_header": "X-UPPER"},
        {"name": "ok", "sig_header": "x-sig", "encoding": "raw"},
        {"name": "ok", "sig_header": "x-sig", "ts_header": "X-TS"},
        {"name": "ok", "sig_header": "x-sig", "signed_template": "{ts}"},
        {"name": "ok", "sig_header": "x-sig", "signed_template": "no-marker"},
    ],
)
def test_invalid_configurations_rejected(kwargs: dict[str, str]) -> None:
    with pytest.raises(ConfigurationError):
        GenericHMAC(**kwargs)


def test_duplicate_registration_requires_replace() -> None:
    provider = GenericHMAC(name="dup-test", sig_header="x-dup", signed_template="{payload}")
    register_provider(provider)
    try:
        with pytest.raises(ConfigurationError):
            register_provider(GenericHMAC(name="dup-test", sig_header="x-dup"))
        register_provider(GenericHMAC(name="dup-test", sig_header="x-dup"), replace=True)
    finally:
        _REGISTRY.pop("dup-test", None)

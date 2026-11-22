"""GitHub legacy SHA-1 scheme tests."""

from __future__ import annotations

import pytest

from conftest import (
    GH_LEGACY_PAYLOAD,
    GH_LEGACY_SECRET,
    GH_LEGACY_SIG,
    GH_LEGACY_SIG_256,
    hmac_sha1_hex,
)
from signedhook import (
    InvalidHeaderFormatError,
    MissingHeaderError,
    SignatureMismatchError,
    verify,
)


def legacy_headers(sig: str = GH_LEGACY_SIG) -> dict[str, str]:
    return {"x-hub-signature": sig}


def test_accepts_independently_computed_vector() -> None:
    result = verify(
        GH_LEGACY_PAYLOAD,
        legacy_headers(),
        secrets=GH_LEGACY_SECRET,
        provider="github-legacy",
        now=1,
    )
    assert result.provider == "github-legacy"
    assert result.scheme == "hmac-sha1"
    assert result.timestamp is None
    assert result.matched_secret_index == 0


def test_auto_detects_legacy_when_modern_header_absent() -> None:
    result = verify(GH_LEGACY_PAYLOAD, legacy_headers(), secrets=GH_LEGACY_SECRET, now=1)
    assert result.provider == "github-legacy"
    assert result.scheme == "hmac-sha1"


def test_auto_prefers_sha256_when_both_headers_present() -> None:
    headers = {"x-hub-signature": GH_LEGACY_SIG, "x-hub-signature-256": GH_LEGACY_SIG_256}
    result = verify(GH_LEGACY_PAYLOAD, headers, secrets=GH_LEGACY_SECRET, now=1)
    assert result.provider == "github"
    assert result.scheme == "hmac-sha256"


def test_strict_legacy_verifies_even_when_both_headers_present() -> None:
    headers = {"x-hub-signature": GH_LEGACY_SIG, "x-hub-signature-256": GH_LEGACY_SIG_256}
    result = verify(
        GH_LEGACY_PAYLOAD, headers, secrets=GH_LEGACY_SECRET, provider="github-legacy", now=1
    )
    assert result.provider == "github-legacy"
    assert result.scheme == "hmac-sha1"


def test_rejects_tampered_payload() -> None:
    with pytest.raises(SignatureMismatchError):
        verify(
            GH_LEGACY_PAYLOAD + b"\n",
            legacy_headers(),
            secrets=GH_LEGACY_SECRET,
            provider="github-legacy",
        )


def test_sha256_prefix_rejected_on_legacy_header() -> None:
    headers = legacy_headers("sha256=" + hmac_sha1_hex(GH_LEGACY_SECRET, GH_LEGACY_PAYLOAD))
    with pytest.raises(InvalidHeaderFormatError) as excinfo:
        verify(GH_LEGACY_PAYLOAD, headers, secrets=GH_LEGACY_SECRET, provider="github-legacy")
    assert "sha1=" in str(excinfo.value)


def test_malformed_hex_rejected() -> None:
    with pytest.raises(InvalidHeaderFormatError):
        verify(
            GH_LEGACY_PAYLOAD,
            legacy_headers("sha1=zz-not-hex"),
            secrets=GH_LEGACY_SECRET,
            provider="github-legacy",
        )


def test_rotation_matches_second_secret() -> None:
    old_secret = "legacy-github-secret-old-0001"
    sig = "sha1=" + hmac_sha1_hex(old_secret, GH_LEGACY_PAYLOAD)
    result = verify(
        GH_LEGACY_PAYLOAD,
        legacy_headers(sig),
        secrets=[GH_LEGACY_SECRET, old_secret],
        provider="github-legacy",
    )
    assert result.matched_secret_index == 1


def test_missing_header_reported() -> None:
    with pytest.raises(MissingHeaderError) as excinfo:
        verify(GH_LEGACY_PAYLOAD, {}, secrets=GH_LEGACY_SECRET, provider="github-legacy")
    assert excinfo.value.header == "x-hub-signature"


def test_no_timestamp_so_no_tolerance_rejection() -> None:
    result = verify(
        GH_LEGACY_PAYLOAD,
        legacy_headers(),
        secrets=GH_LEGACY_SECRET,
        provider="github-legacy",
        now=1 + 10_000_000,
    )
    assert result.provider == "github-legacy"

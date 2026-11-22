"""GitHub scheme tests."""

from __future__ import annotations

import pytest

from conftest import GH_SECRET, GH_SIG, PAYLOAD, hmac_sha256_hex
from signedhook import InvalidHeaderFormatError, SignatureMismatchError, verify


def gh_headers(sig: str = GH_SIG) -> dict[str, str]:
    return {"x-hub-signature-256": sig}


def test_accepts_independently_computed_vector() -> None:
    result = verify(PAYLOAD, gh_headers(), secrets=GH_SECRET, provider="github", now=1)
    assert result.provider == "github"
    assert result.timestamp is None
    assert result.message_key is None


def test_no_timestamp_so_no_tolerance_rejection() -> None:
    result = verify(PAYLOAD, gh_headers(), secrets=GH_SECRET, provider="github", now=NOW_FAR)
    assert result.provider == "github"


NOW_FAR = 1 + 10_000_000


def test_rejects_tampered_payload() -> None:
    with pytest.raises(SignatureMismatchError):
        verify(PAYLOAD + b"\n", gh_headers(), secrets=GH_SECRET, provider="github")


def test_missing_prefix_rejected() -> None:
    raw = hmac_sha256_hex(GH_SECRET, PAYLOAD)
    with pytest.raises(InvalidHeaderFormatError):
        verify(PAYLOAD, gh_headers(raw), secrets=GH_SECRET, provider="github")


def test_sha1_prefix_rejected() -> None:
    sig = "sha1=" + hmac_sha256_hex(GH_SECRET, PAYLOAD)
    with pytest.raises(InvalidHeaderFormatError) as excinfo:
        verify(PAYLOAD, gh_headers(sig), secrets=GH_SECRET, provider="github")
    assert "sha256=" in str(excinfo.value)


def test_malformed_hex_rejected() -> None:
    with pytest.raises(InvalidHeaderFormatError):
        verify(PAYLOAD, gh_headers("sha256=zz-not-hex"), secrets=GH_SECRET, provider="github")


def test_rotation_matches_second_secret() -> None:
    old_secret = "github-webhook-secret-old-00000001"
    sig = "sha256=" + hmac_sha256_hex(old_secret, PAYLOAD)
    result = verify(PAYLOAD, gh_headers(sig), secrets=[GH_SECRET, old_secret], provider="github")
    assert result.matched_secret_index == 1


def test_missing_header_reported() -> None:
    from signedhook import MissingHeaderError

    with pytest.raises(MissingHeaderError) as excinfo:
        verify(PAYLOAD, {}, secrets=GH_SECRET, provider="github")
    assert excinfo.value.header == "x-hub-signature-256"

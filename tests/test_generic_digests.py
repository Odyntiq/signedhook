"""GenericHMAC digest selection and millisecond-timestamp tests."""

from __future__ import annotations

import hashlib
import hmac

import pytest

from conftest import (
    GENERIC512_SIG_B64,
    GENERIC_PAYLOAD,
    GENERIC_SECRET,
    MS_SECONDS_SIG,
    MS_SECONDS_TS,
    MS_SECRET,
    MS_SIG,
    MS_TS,
)
from signedhook import ConfigurationError, GenericHMAC, register_provider, verify


def sha512_provider() -> GenericHMAC:
    return GenericHMAC(
        name="acme512",
        sig_header="x-acme-sig",
        encoding="base64",
        digest="sha512",
        signed_template="{payload}",
    )


def ms_provider(name: str = "acme-ms", ts_unit: str = "milliseconds") -> GenericHMAC:
    return GenericHMAC(
        name=name,
        sig_header="x-acme-sig",
        sig_prefix="v1=",
        ts_header="x-acme-ts",
        signed_template="{ts}|{payload}",
        ts_unit=ts_unit,
    )


def register(provider: GenericHMAC) -> None:
    """Register for the duration of the suite (re-registration allowed)."""
    register_provider(provider, replace=True)


def ms_headers(sig: str = MS_SIG, ts: int = MS_TS) -> dict[str, str]:
    return {"x-acme-sig": sig, "x-acme-ts": str(ts)}


class TestDigestSelection:
    def test_sha512_base64_vector(self) -> None:
        provider = sha512_provider()
        register(provider)
        result = verify(
            GENERIC_PAYLOAD,
            {"x-acme-sig": GENERIC512_SIG_B64},
            secrets=GENERIC_SECRET,
            provider="acme512",
            now=1,
        )
        assert result.provider == "acme512"
        assert result.scheme == "hmac-sha512"

    def test_sha1_digest_vector(self) -> None:
        provider = GenericHMAC(
            name="acme1",
            sig_header="x-acme-sig",
            sig_prefix="sha1=",
            digest="sha1",
            signed_template="{payload}",
        )
        register(provider)
        expected = hmac.new(
            GENERIC_SECRET.encode("utf-8"), GENERIC_PAYLOAD, hashlib.sha1
        ).hexdigest()
        result = verify(
            GENERIC_PAYLOAD,
            {"x-acme-sig": f"sha1={expected}"},
            secrets=GENERIC_SECRET,
            provider="acme1",
            now=1,
        )
        assert result.scheme == "hmac-sha1"

    def test_sha384_digest_vector(self) -> None:
        provider = GenericHMAC(
            name="acme384",
            sig_header="x-acme-sig",
            digest="sha384",
            signed_template="{payload}",
        )
        register(provider)
        expected = hmac.new(
            GENERIC_SECRET.encode("utf-8"), GENERIC_PAYLOAD, hashlib.sha384
        ).hexdigest()
        result = verify(
            GENERIC_PAYLOAD,
            {"x-acme-sig": expected},
            secrets=GENERIC_SECRET,
            provider="acme384",
            now=1,
        )
        assert result.scheme == "hmac-sha384"

    def test_invalid_digest_rejected(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            GenericHMAC(name="bad", sig_header="x-sig", digest="md5")
        assert "digest" in str(excinfo.value)

    def test_default_remains_sha256(self) -> None:
        provider = GenericHMAC(name="acme-default", sig_header="x-sig")
        assert provider.scheme == "hmac-sha256"
        assert provider.digest == "sha256"


class TestMillisecondTimestamps:
    def test_millisecond_vector_normalises_result_and_tolerance(self) -> None:
        provider = ms_provider()
        register(provider)
        result = verify(
            GENERIC_PAYLOAD,
            ms_headers(),
            secrets=MS_SECRET,
            provider="acme-ms",
            now=MS_SECONDS_TS + 10,
        )
        assert result.provider == "acme-ms"
        assert result.timestamp == MS_SECONDS_TS

    def test_millisecond_outside_tolerance_rejected(self) -> None:
        from signedhook import TimestampToleranceExceededError

        provider = ms_provider()
        register(provider)
        with pytest.raises(TimestampToleranceExceededError):
            verify(
                GENERIC_PAYLOAD,
                ms_headers(),
                secrets=MS_SECRET,
                provider="acme-ms",
                now=MS_SECONDS_TS + 10_000,
            )

    def test_template_receives_raw_millisecond_value(self) -> None:
        # MS_SIG was computed over f"{MS_TS}|{payload}" with the raw
        # millisecond value, so a passing verification proves the template
        # sees the raw value, not the normalised seconds.
        provider = ms_provider()
        register(provider)
        result = verify(
            GENERIC_PAYLOAD,
            ms_headers(),
            secrets=MS_SECRET,
            provider="acme-ms",
            tolerance=None,
            now=1,
        )
        assert result.provider == "acme-ms"

    def test_auto_detects_milliseconds(self) -> None:
        provider = ms_provider(name="acme-auto", ts_unit="auto")
        register(provider)
        result = verify(
            GENERIC_PAYLOAD,
            ms_headers(),
            secrets=MS_SECRET,
            provider="acme-auto",
            now=MS_SECONDS_TS + 10,
        )
        assert result.timestamp == MS_SECONDS_TS

    def test_auto_detects_seconds(self) -> None:
        provider = ms_provider(name="acme-auto", ts_unit="auto")
        register(provider)
        result = verify(
            GENERIC_PAYLOAD,
            ms_headers(sig=MS_SECONDS_SIG, ts=MS_SECONDS_TS),
            secrets=MS_SECRET,
            provider="acme-auto",
            now=MS_SECONDS_TS + 10,
        )
        assert result.timestamp == MS_SECONDS_TS

    def test_explicit_seconds_unit_rejects_millisecond_value(self) -> None:
        # With ts_unit="seconds" the 13-digit value is treated as far-future
        # seconds, so the tolerance check must reject it.
        from signedhook import TimestampToleranceExceededError

        provider = ms_provider(name="acme-sec", ts_unit="seconds")
        register(provider)
        with pytest.raises(TimestampToleranceExceededError):
            verify(
                GENERIC_PAYLOAD,
                ms_headers(),
                secrets=MS_SECRET,
                provider="acme-sec",
                now=MS_SECONDS_TS + 10,
                tolerance=300,
            )

    def test_invalid_ts_unit_rejected(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            GenericHMAC(name="bad", sig_header="x-sig", ts_unit="nanoseconds")
        assert "ts_unit" in str(excinfo.value)

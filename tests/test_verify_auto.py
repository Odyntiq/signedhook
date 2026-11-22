"""Auto-detection, strict mode, payload guards and settings plumbing."""

from __future__ import annotations

import pytest

from conftest import (
    GH_SECRET,
    GH_SIG,
    NOW,
    PAYLOAD,
    RAZORPAY_SECRET,
    RAZORPAY_SIG,
    SHOPIFY_SECRET,
    SHOPIFY_SIG,
    SLACK_SECRET,
    SLACK_SIG,
    STD_SECRET_HEADER,
    STRIPE_SECRET,
    STRIPE_SIG,
    std_headers,
    stripe_headers,
)
from signedhook import (
    PayloadTooLargeError,
    Settings,
    UnknownProviderError,
    verify,
)
from signedhook._providers import _REGISTRY

AUTO_CASES = [
    ("standard", std_headers(), STD_SECRET_HEADER, NOW),
    ("stripe", {"stripe-signature": STRIPE_SIG}, STRIPE_SECRET, NOW),
    ("github", {"x-hub-signature-256": GH_SIG}, GH_SECRET, None),
    (
        "slack",
        {"x-slack-signature": SLACK_SIG, "x-slack-request-timestamp": str(NOW)},
        SLACK_SECRET,
        NOW,
    ),
    ("shopify", {"x-shopify-hmac-sha256": SHOPIFY_SIG}, SHOPIFY_SECRET, None),
    ("razorpay", {"x-razorpay-signature": RAZORPAY_SIG}, RAZORPAY_SECRET, None),
]


@pytest.mark.parametrize(
    "expected_provider,headers,secrets,now", AUTO_CASES, ids=[c[0] for c in AUTO_CASES]
)
def test_auto_detection_finds_each_provider(
    expected_provider: str,
    headers: dict[str, str],
    secrets: str,
    now: int | None,
) -> None:
    kwargs = {} if now is None else {"now": now}
    result = verify(PAYLOAD, headers, secrets=secrets, provider="auto", **kwargs)
    assert result.provider == expected_provider


def test_provider_none_behaves_like_auto() -> None:
    result = verify(PAYLOAD, std_headers(), secrets=STD_SECRET_HEADER, provider=None, now=NOW)
    assert result.provider == "standard"


def test_unknown_strict_provider_lists_known_names() -> None:
    with pytest.raises(UnknownProviderError) as excinfo:
        verify(PAYLOAD, stripe_headers(), secrets=STRIPE_SECRET, provider="nope", now=NOW)
    assert "standard" in excinfo.value.candidates
    assert "stripe" in excinfo.value.candidates


def test_no_matching_headers_reports_unknown_provider() -> None:
    with pytest.raises(UnknownProviderError) as excinfo:
        verify(PAYLOAD, {"x-unrelated": "1"}, secrets=STRIPE_SECRET, now=NOW)
    assert excinfo.value.code == "unknown_provider"


def test_ambiguous_headers_report_candidates() -> None:
    from signedhook import GenericHMAC

    shadow = GenericHMAC(
        name="stripe-shadow", sig_header="stripe-signature", signed_template="{payload}"
    )
    _REGISTRY[shadow.name] = shadow
    try:
        with pytest.raises(UnknownProviderError) as excinfo:
            verify(PAYLOAD, stripe_headers(), secrets=STRIPE_SECRET, provider="auto", now=NOW)
        assert set(excinfo.value.candidates) == {"stripe", "stripe-shadow"}
    finally:
        _REGISTRY.pop("stripe-shadow", None)


def test_str_payload_rejected_with_guidance() -> None:
    with pytest.raises(TypeError) as excinfo:
        verify('{"json":"as str"}', stripe_headers(), secrets=STRIPE_SECRET, now=NOW)  # type: ignore[arg-type]
    assert "raw bytes" in str(excinfo.value)


def test_oversized_payload_rejected_before_signature_work() -> None:
    settings = Settings(max_payload_bytes=512)
    with pytest.raises(PayloadTooLargeError) as excinfo:
        verify(
            b"x" * 600,
            stripe_headers(),
            secrets=STRIPE_SECRET,
            provider="stripe",
            now=NOW,
            settings=settings,
        )
    assert excinfo.value.limit == 512
    assert excinfo.value.code == "payload_too_large"


def test_tolerance_parameter_overrides_settings() -> None:
    with pytest.raises(Exception, match="tolerance"):
        verify(
            PAYLOAD,
            stripe_headers(),
            secrets=STRIPE_SECRET,
            provider="stripe",
            now=NOW + 15,
            tolerance=10,
        )


def test_tolerance_disabled_via_none() -> None:
    result = verify(
        PAYLOAD,
        stripe_headers(),
        secrets=STRIPE_SECRET,
        provider="stripe",
        now=NOW + 5000,
        tolerance=None,
    )
    assert result.provider == "stripe"


def test_settings_env_plumbing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERIHOOK_TOLERANCE_SECONDS", "30")
    monkeypatch.setenv("VERIHOOK_MAX_PAYLOAD_BYTES", "4096")
    settings = Settings.from_env()
    assert settings.tolerance_seconds == 30
    assert settings.max_payload_bytes == 4096
    with pytest.raises(Exception, match="tolerance"):
        verify(
            PAYLOAD,
            stripe_headers(),
            secrets=STRIPE_SECRET,
            provider="stripe",
            now=NOW + 31,
            settings=settings,
        )


def test_settings_env_none_disables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("VERIHOOK_TOLERANCE_SECONDS", "none")
    settings = Settings.from_env()
    assert settings.tolerance_seconds is None
    result = verify(
        PAYLOAD,
        stripe_headers(),
        secrets=STRIPE_SECRET,
        provider="stripe",
        now=NOW + 99999,
        settings=settings,
    )
    assert result.provider == "stripe"


def test_empty_secret_sequence_rejected() -> None:
    from signedhook import ConfigurationError

    with pytest.raises(ConfigurationError):
        verify(PAYLOAD, stripe_headers(), secrets=[], provider="stripe", now=NOW)


def test_non_string_secret_rejected() -> None:
    with pytest.raises(TypeError):
        verify(PAYLOAD, stripe_headers(), secrets=["ok", 42], provider="stripe", now=NOW)  # type: ignore[list-item]

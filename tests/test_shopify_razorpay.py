"""Shopify and Razorpay scheme tests (base64 vs hex over the raw payload)."""

from __future__ import annotations

import pytest

from conftest import PAYLOAD, RAZORPAY_SECRET, RAZORPAY_SIG, SHOPIFY_SECRET, SHOPIFY_SIG
from signedhook import InvalidHeaderFormatError, SignatureMismatchError, verify


def test_shopify_accepts_independently_computed_vector() -> None:
    result = verify(
        PAYLOAD,
        {"x-shopify-hmac-sha256": SHOPIFY_SIG},
        secrets=SHOPIFY_SECRET,
        provider="shopify",
    )
    assert result.provider == "shopify"


def test_shopify_rejects_tampered_payload() -> None:
    with pytest.raises(SignatureMismatchError):
        verify(
            PAYLOAD + b" ",
            {"x-shopify-hmac-sha256": SHOPIFY_SIG},
            secrets=SHOPIFY_SECRET,
            provider="shopify",
        )


def test_razorpay_accepts_independently_computed_vector() -> None:
    result = verify(
        PAYLOAD,
        {"x-razorpay-signature": RAZORPAY_SIG},
        secrets=RAZORPAY_SECRET,
        provider="razorpay",
    )
    assert result.provider == "razorpay"


def test_razorpay_rejects_tampered_payload() -> None:
    with pytest.raises(SignatureMismatchError):
        verify(
            PAYLOAD + b" ",
            {"x-razorpay-signature": RAZORPAY_SIG},
            secrets=RAZORPAY_SECRET,
            provider="razorpay",
        )


def test_razorpay_rejects_non_hex_signature() -> None:
    with pytest.raises(InvalidHeaderFormatError):
        verify(
            PAYLOAD,
            {"x-razorpay-signature": "not-hex-at-all!"},
            secrets=RAZORPAY_SECRET,
            provider="razorpay",
        )


def test_shopify_rejects_non_base64_signature() -> None:
    with pytest.raises(InvalidHeaderFormatError):
        verify(
            PAYLOAD,
            {"x-shopify-hmac-sha256": "!!!not-b64!!!"},
            secrets=SHOPIFY_SECRET,
            provider="shopify",
        )

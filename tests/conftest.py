"""Shared constants and helpers for the signedhook test suite.

Canonical signature literals (STD_SIG, STRIPE_SIG, GH_SIG, SLACK_SIG,
SHOPIFY_SIG, RAZORPAY_SIG) were computed independently of the library from
the public scheme definitions (scripts/vectors_2026-11-22.py), so provider
tests validate scheme constants rather than the library mirroring itself.
Dynamic cases recompute signatures directly with hmac/hashlib.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

NOW = 1700000000
PAYLOAD = b'{"event":"ping","seq":1}'

# --- Standard Webhooks / Svix ---
STD_RAW_KEY = b"0123456789abcdef0123456789abcdef"
STD_SECRET_HEADER = "whsec_MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
STD_ID = "msg_test_0001"
STD_SIG = "v1,djImUh1/sNJLOafJC2LiBXTKmB5ta6ghP9WaWltko+I="

# --- Stripe ---
STRIPE_SECRET = "whsec_test_stripe_secret_key_0001"
STRIPE_SIG = "t=1700000000,v1=5d6fbdbb1a8bd79872081094ed57d517ac9068801dcc94c821c752efb9dcb5fe"

# --- GitHub ---
GH_SECRET = "github-webhook-secret-test-0001"
GH_SIG = "sha256=cebdb2c00051d6a48a4f5c71df361de4d74303b79479e4a984211c62f76f7898"

# --- Slack ---
SLACK_SECRET = "slack-signing-secret-test-000001"
SLACK_SIG = "v0=ea709dad64fd83b139aa23c16f116d60391e4076ed5e740e2916332de17711a3"

# --- Shopify ---
SHOPIFY_SECRET = "shopify-webhook-secret-test-00001"
SHOPIFY_SIG = "txNR9zSP5Zh545ZGXtrf4f50Y1te1txEGOQGyJot4vo="

# --- Razorpay ---
RAZORPAY_SECRET = "razorpay-webhook-secret-test-00001"
RAZORPAY_SIG = "14f2f5d3b5954ffe51a880fa3271d6a99325c40acdb862b42e923f08b2c80628"


def hmac_sha256_hex(key: str | bytes, message: bytes) -> str:
    """Hex HMAC-SHA256, used to build dynamic expected signatures."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(key_bytes, message, hashlib.sha256).hexdigest()


def hmac_sha256_b64(key: str | bytes, message: bytes) -> str:
    """Base64 HMAC-SHA256, used to build dynamic expected signatures."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return base64.b64encode(hmac.new(key_bytes, message, hashlib.sha256).digest()).decode("ascii")


def std_headers(sig: str = STD_SIG, webhook_id: str = STD_ID, ts: int = NOW) -> dict[str, str]:
    return {"webhook-id": webhook_id, "webhook-timestamp": str(ts), "webhook-signature": sig}


def stripe_headers(sig: str = STRIPE_SIG) -> dict[str, str]:
    return {"stripe-signature": sig}

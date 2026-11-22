"""Shared constants and helpers for the signedhook test suite.

Canonical signature literals (STD_SIG, STRIPE_SIG, GH_SIG, GH_LEGACY_SIG,
SLACK_SIG, SHOPIFY_SIG, RAZORPAY_SIG, TWILIO_SIG, GENERIC512_SIG, MS_SIG)
were computed independently of the library from the public scheme
definitions (raw hmac/hashlib/base64 derivations outside the test suite), so
provider tests validate scheme constants rather than the library mirroring
itself. Dynamic cases recompute signatures directly with hmac/hashlib.
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

# --- GitHub legacy SHA-1 (independent vector: raw hmac-sha1 over the body) ---
GH_LEGACY_SECRET = "legacy-github-secret"
GH_LEGACY_PAYLOAD = b'{"zen":"Keep it logically awesome."}'
GH_LEGACY_SIG = "sha1=456dae382027b48db330c69ec56dded65a32058e"
GH_LEGACY_SIG_256 = "sha256=03bc2096477d2029b8552ba6008508e4920e994348df41462fb6d399c7af0166"

# --- Slack ---
SLACK_SECRET = "slack-signing-secret-test-000001"
SLACK_SIG = "v0=ea709dad64fd83b139aa23c16f116d60391e4076ed5e740e2916332de17711a3"

# --- Shopify ---
SHOPIFY_SECRET = "shopify-webhook-secret-test-00001"
SHOPIFY_SIG = "txNR9zSP5Zh545ZGXtrf4f50Y1te1txEGOQGyJot4vo="

# --- Razorpay ---
RAZORPAY_SECRET = "razorpay-webhook-secret-test-00001"
RAZORPAY_SIG = "14f2f5d3b5954ffe51a880fa3271d6a99325c40acdb862b42e923f08b2c80628"

# --- Twilio (independent vector: base64 hmac-sha1 over url + sorted k+v) ---
TWILIO_TOKEN = "0123456789abcdef0123456789abcdef"
TWILIO_URL = "https://example.com/twilio?x=1&y=2"
TWILIO_PARAMS = {
    "CallStatus": "completed",
    "From": "+14157779999",
    "Called": "+14155551234",
    "AccountSid": "ACeeeeeeeeeeeeeeeeeeeeeeeeeeee",
}
TWILIO_SIG = "8crMHvtzMtuihIW+zw0BJ155iR0="
TWILIO_PAIRS = [("b", "2"), ("a", "1"), ("b", "1")]
TWILIO_PAIRS_SIG = "qfnFsK4CbVan6hIJ0CQB7CaiaHE="

# --- Generic digests / millisecond timestamps (independent vectors) ---
GENERIC_SECRET = "acme-secret"
GENERIC_PAYLOAD = b'{"event":"ping"}'
GENERIC512_SIG_B64 = (
    "mXzoPx1xaJO/BcMo6D4AdSiM4upH2fuE901r4Ug+BAMBOaq3NPm/ckkuox4gKUdF+EtShySBmxybs3o872/i9g=="
)
MS_SECRET = "acme-ms-secret"
MS_TS = 1_732_297_200_123  # milliseconds; 1732297200 in seconds
MS_SIG = "v1=659161f7f5422f968c81048c2aea8aee5e7520e569e2cc7481f19b155d429b22"
MS_SECONDS_TS = 1_732_297_200
MS_SECONDS_SIG = "v1=3a30b33b1eb78f00d6b5299d98d89e108f5a92e703ed4a1af9798aad9fe3705f"


def hmac_sha256_hex(key: str | bytes, message: bytes) -> str:
    """Hex HMAC-SHA256, used to build dynamic expected signatures."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(key_bytes, message, hashlib.sha256).hexdigest()


def hmac_sha256_b64(key: str | bytes, message: bytes) -> str:
    """Base64 HMAC-SHA256, used to build dynamic expected signatures."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return base64.b64encode(hmac.new(key_bytes, message, hashlib.sha256).digest()).decode("ascii")


def hmac_sha1_hex(key: str | bytes, message: bytes) -> str:
    """Hex HMAC-SHA1, used to build dynamic expected signatures."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(key_bytes, message, hashlib.sha1).hexdigest()


def hmac_sha1_b64(key: str | bytes, message: bytes) -> str:
    """Base64 HMAC-SHA1, used to build dynamic expected signatures."""
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return base64.b64encode(hmac.new(key_bytes, message, hashlib.sha1).digest()).decode("ascii")


def std_headers(sig: str = STD_SIG, webhook_id: str = STD_ID, ts: int = NOW) -> dict[str, str]:
    return {"webhook-id": webhook_id, "webhook-timestamp": str(ts), "webhook-signature": sig}


def stripe_headers(sig: str = STRIPE_SIG) -> dict[str, str]:
    return {"stripe-signature": sig}

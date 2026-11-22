"""Razorpay webhook signature scheme.

Scheme (per Razorpay's public documentation):

- ``X-Razorpay-Signature``: ``<hex hmac-sha256>`` over the raw payload.
- The signing secret is a plain UTF-8 string from the Razorpay dashboard.
- The scheme signs no timestamp; dedupe deliveries by the ``X-Razorpay-Event-Id``
  header via ``verify_with_replay``.
"""

from __future__ import annotations

from .._encoding import decode_secret, decode_signature
from .base import HeaderMap, ParsedSignature, Provider, _require

__all__ = ["RazorpayProvider"]


class RazorpayProvider(Provider):
    """Verifier for Razorpay's ``X-Razorpay-Signature`` scheme."""

    name = "razorpay"
    scheme = "hmac-sha256"
    required_headers = ("x-razorpay-signature",)
    signature_header = "x-razorpay-signature"
    timestamp_header = None

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        raw = _require(headers, self.signature_header).strip()
        signature = decode_signature(raw, "hex", self.signature_header)
        return ParsedSignature(signatures=(signature,), timestamp=None, message_key=None)

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        return payload

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(secret, strip_prefix=None, base64_encoded=False)

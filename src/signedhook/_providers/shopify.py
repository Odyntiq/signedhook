"""Shopify webhook signature scheme.

Scheme (per Shopify's public documentation):

- ``X-Shopify-Hmac-Sha256``: ``<base64 hmac-sha256>`` over the raw payload.
- The signing secret is a plain UTF-8 string (from the app's webhook
  configuration).
- The scheme signs no timestamp; dedupe webhook deliveries by the
  ``X-Shopify-Webhook-Id`` header via ``verify_with_replay``.
"""

from __future__ import annotations

from .._encoding import decode_secret
from .base import HeaderMap, ParsedSignature, Provider, _base64_signature

__all__ = ["ShopifyProvider"]


class ShopifyProvider(Provider):
    """Verifier for Shopify's ``X-Shopify-Hmac-Sha256`` scheme."""

    name = "shopify"
    scheme = "hmac-sha256"
    required_headers = ("x-shopify-hmac-sha256",)
    signature_header = "x-shopify-hmac-sha256"
    timestamp_header = None

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        signature = _base64_signature(headers, self.signature_header, prefix="")
        return ParsedSignature(signatures=(signature,), timestamp=None, message_key=None)

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        return payload

    def streaming_parts(self, headers: HeaderMap, parsed: ParsedSignature) -> tuple[bytes, bytes]:
        return b"", b""

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(secret, strip_prefix=None, base64_encoded=False)

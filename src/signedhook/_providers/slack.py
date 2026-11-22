"""Slack webhook signature scheme.

Scheme (per Slack's public documentation):

- ``X-Slack-Request-Timestamp``: Unix seconds.
- ``X-Slack-Signature``: ``v0=<hex hmac-sha256>`` over
  ``"v0:{timestamp}:{payload}"``.
- The signing secret is a plain UTF-8 string.
- Slack retries carry a fresh timestamp and signature, so the parsed
  (timestamp, signature) pair is a sound replay key.
"""

from __future__ import annotations

from .._encoding import decode_secret, decode_signature
from .._errors import InvalidHeaderFormatError
from .base import HeaderMap, ParsedSignature, Provider, _require, _timestamp

__all__ = ["SlackProvider"]


class SlackProvider(Provider):
    """Verifier for Slack's ``X-Slack-Signature`` scheme."""

    name = "slack"
    scheme = "hmac-sha256"
    required_headers = ("x-slack-signature", "x-slack-request-timestamp")
    signature_header = "x-slack-signature"
    timestamp_header = "x-slack-request-timestamp"

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        raw = _require(headers, self.signature_header).strip()
        prefix = "v0="
        if not raw.startswith(prefix):
            raise InvalidHeaderFormatError(self.signature_header, f"expected {prefix!r} prefix")
        signature = decode_signature(raw[len(prefix) :], "hex", self.signature_header)
        timestamp = _timestamp(headers, self.timestamp_header)
        return ParsedSignature(signatures=(signature,), timestamp=timestamp, message_key=None)

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        if parsed.timestamp is None:
            raise InvalidHeaderFormatError(self.signature_header, "missing request timestamp")
        return b"v0:" + str(parsed.timestamp).encode("ascii") + b":" + payload

    def streaming_parts(self, headers: HeaderMap, parsed: ParsedSignature) -> tuple[bytes, bytes]:
        if parsed.timestamp is None:
            raise InvalidHeaderFormatError(self.signature_header, "missing request timestamp")
        return b"v0:" + str(parsed.timestamp).encode("ascii") + b":", b""

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(secret, strip_prefix=None, base64_encoded=False)

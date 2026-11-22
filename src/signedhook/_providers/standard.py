"""Standard Webhooks scheme (also used by Svix).

Scheme (per the published Standard Webhooks specification):

- ``webhook-id``: unique message id, carried as the replay key.
- ``webhook-timestamp``: Unix seconds.
- ``webhook-signature``: space-separated entries of the form
  ``v1,<base64 hmac-sha256>`` over ``"{id}.{timestamp}.{payload}"``.
- Secrets are transmitted as ``whsec_`` + base64 of the raw key; raw UTF-8
  secrets are accepted as a fallback, mirroring the ecosystem convention.
"""

from __future__ import annotations

from .._encoding import decode_secret, decode_signature
from .._errors import ConfigurationError, InvalidHeaderFormatError
from .base import HeaderMap, ParsedSignature, Provider, _require, _timestamp

__all__ = ["StandardWebhooksProvider"]


class StandardWebhooksProvider(Provider):
    """Verifier for the Standard Webhooks / Svix signature scheme."""

    name = "standard"
    scheme = "hmac-sha256"
    required_headers = ("webhook-id", "webhook-timestamp", "webhook-signature")
    signature_header = "webhook-signature"
    timestamp_header = "webhook-timestamp"

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        raw = _require(headers, self.signature_header)
        webhook_id = _require(headers, "webhook-id")
        timestamp = _timestamp(headers, self.timestamp_header)

        signatures: list[bytes] = []
        for entry in raw.split(" "):
            entry = entry.strip()
            if not entry:
                continue
            if entry.startswith("v1,"):
                entry = entry[len("v1,") :]
            signatures.append(decode_signature(entry, "base64", self.signature_header))
        if not signatures:
            raise InvalidHeaderFormatError(self.signature_header, "no signatures present")
        return ParsedSignature(
            signatures=tuple(signatures),
            timestamp=timestamp,
            message_key=webhook_id,
        )

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        webhook_id = _require(headers, "webhook-id")
        if parsed.timestamp is None:
            raise ConfigurationError("standard scheme requires a signed timestamp")
        return (
            webhook_id.encode("utf-8")
            + b"."
            + str(parsed.timestamp).encode("ascii")
            + b"."
            + payload
        )

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(secret, strip_prefix="whsec_", base64_encoded=None)

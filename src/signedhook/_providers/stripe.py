"""Stripe webhook signature scheme.

Scheme (per Stripe's public documentation):

- ``Stripe-Signature``: comma-separated ``k=v`` components — ``t=<unix
  seconds>`` and one or more ``v1=<hex hmac-sha256>`` entries computed over
  ``"{timestamp}.{payload}"``.
- Secrets use the ``whsec_`` prefix; the prefix is stripped before use.
- Stripe retries produce a fresh timestamp and signature per delivery, so the
  parsed (timestamp, signature) pair is a sound replay key for Stripe
  deliveries.
"""

from __future__ import annotations

from .._encoding import decode_secret, decode_signature, parse_timestamp
from .._errors import InvalidHeaderFormatError
from .base import HeaderMap, ParsedSignature, Provider, _require

__all__ = ["StripeProvider"]


class StripeProvider(Provider):
    """Verifier for Stripe's ``Stripe-Signature`` scheme."""

    name = "stripe"
    scheme = "hmac-sha256"
    required_headers = ("stripe-signature",)
    signature_header = "stripe-signature"
    timestamp_header = None

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        raw = _require(headers, self.signature_header)
        timestamp: int | None = None
        signatures: list[bytes] = []
        for component in raw.split(","):
            component = component.strip()
            if not component:
                continue
            key, sep, value = component.partition("=")
            if not sep:
                raise InvalidHeaderFormatError(
                    self.signature_header, "expected k=v components separated by commas"
                )
            key = key.strip()
            value = value.strip()
            if key == "t":
                if timestamp is not None:
                    raise InvalidHeaderFormatError(
                        self.signature_header, "duplicate t= timestamp component"
                    )
                timestamp = parse_timestamp(value, self.signature_header)
            elif key == "v1":
                signatures.append(decode_signature(value, "hex", self.signature_header))
            # Other keys (legacy v0, platform whk_ ids) are ignored by design.
        if timestamp is None:
            raise InvalidHeaderFormatError(self.signature_header, "missing t= timestamp component")
        if not signatures:
            raise InvalidHeaderFormatError(
                self.signature_header, "no v1= signature component present"
            )
        return ParsedSignature(signatures=tuple(signatures), timestamp=timestamp, message_key=None)

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        if parsed.timestamp is None:
            raise InvalidHeaderFormatError(self.signature_header, "missing t= timestamp component")
        return str(parsed.timestamp).encode("ascii") + b"." + payload

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(secret, strip_prefix="whsec_", base64_encoded=False)

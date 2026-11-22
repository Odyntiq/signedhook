"""GitHub webhook signature scheme.

Scheme (per GitHub's public documentation):

- ``X-Hub-Signature-256``: ``sha256=<hex hmac-sha256>`` over the raw payload.
- The secret is a plain UTF-8 string.
- The scheme signs no timestamp, so tolerance checks do not apply; use the
  ``X-GitHub-Delivery`` header as the replay key via ``verify_with_replay``.
- The legacy SHA-1 ``X-Hub-Signature`` header is intentionally unsupported
  (SHA-1 HMACs should no longer be trusted); GitHub sends the SHA-256 header
  for all new deliveries.
"""

from __future__ import annotations

from .._encoding import decode_secret, decode_signature
from .._errors import InvalidHeaderFormatError
from .base import HeaderMap, ParsedSignature, Provider, _require

__all__ = ["GitHubProvider"]


class GitHubProvider(Provider):
    """Verifier for GitHub's ``X-Hub-Signature-256`` scheme."""

    name = "github"
    scheme = "hmac-sha256"
    required_headers = ("x-hub-signature-256",)
    signature_header = "x-hub-signature-256"
    timestamp_header = None

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        raw = _require(headers, self.signature_header).strip()
        prefix = "sha256="
        if not raw.startswith(prefix):
            raise InvalidHeaderFormatError(self.signature_header, f"expected {prefix!r} prefix")
        signature = decode_signature(raw[len(prefix) :], "hex", self.signature_header)
        return ParsedSignature(signatures=(signature,), timestamp=None, message_key=None)

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        return payload

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(secret, strip_prefix=None, base64_encoded=False)

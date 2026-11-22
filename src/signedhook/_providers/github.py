"""GitHub webhook signature schemes.

Schemes (per GitHub's public documentation):

- ``X-Hub-Signature-256``: ``sha256=<hex hmac-sha256>`` over the raw payload
  (:class:`GitHubProvider`).
- ``X-Hub-Signature``: ``sha1=<hex hmac-sha1>`` over the raw payload
  (:class:`GitHubLegacyProvider`) — the original scheme, still sent by
  GitHub on every delivery alongside the SHA-256 header.
- The secret is a plain UTF-8 string.
- Neither scheme signs a timestamp, so tolerance checks do not apply; use the
  ``X-GitHub-Delivery`` header as the replay key via ``verify_with_replay``.

GitHub sends both headers on new deliveries, so auto-detection prefers the
SHA-256 scheme: :class:`GitHubLegacyProvider` only matches when the modern
header is absent. Pass ``provider="github-legacy"`` to verify the legacy
header explicitly (for example when replaying historical deliveries). Note
that HMAC-SHA1 is not broken as a MAC construction; the SHA-256 scheme is
still preferred wherever available.
"""

from __future__ import annotations

from .._encoding import decode_secret, decode_signature
from .._errors import InvalidHeaderFormatError
from .base import HeaderMap, ParsedSignature, Provider, _require

__all__ = ["GitHubLegacyProvider", "GitHubProvider"]


class GitHubProvider(Provider):
    """Verifier for GitHub's ``X-Hub-Signature-256`` scheme."""

    name = "github"
    scheme = "hmac-sha256"
    digest = "sha256"
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


class GitHubLegacyProvider(Provider):
    """Verifier for GitHub's legacy ``X-Hub-Signature`` SHA-1 scheme."""

    name = "github-legacy"
    scheme = "hmac-sha1"
    digest = "sha1"
    required_headers = ("x-hub-signature",)
    signature_header = "x-hub-signature"
    timestamp_header = None

    def detect(self, headers: HeaderMap) -> bool:
        """Match only when the modern SHA-256 header is absent.

        GitHub delivers both headers; the SHA-256 scheme wins auto-detection
        so the stronger algorithm is always preferred when available.
        """
        return "x-hub-signature" in headers and "x-hub-signature-256" not in headers

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        raw = _require(headers, self.signature_header).strip()
        prefix = "sha1="
        if not raw.startswith(prefix):
            raise InvalidHeaderFormatError(self.signature_header, f"expected {prefix!r} prefix")
        signature = decode_signature(raw[len(prefix) :], "hex", self.signature_header)
        return ParsedSignature(signatures=(signature,), timestamp=None, message_key=None)

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        return payload

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(secret, strip_prefix=None, base64_encoded=False)

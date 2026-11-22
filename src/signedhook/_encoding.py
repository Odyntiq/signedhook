"""Encoding, decoding and constant-time comparison helpers.

Shared by every provider scheme so all of them behave identically on the
security-critical paths. None of these helpers log or embed secret material.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac

from ._errors import ConfigurationError, InvalidHeaderFormatError

__all__ = [
    "canonical_hmac_sha256",
    "constant_time_eq",
    "decode_secret",
    "decode_signature",
    "parse_timestamp",
]


def canonical_hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Return the raw HMAC-SHA256 digest of ``message`` under ``key``."""
    return hmac.new(key, message, hashlib.sha256).digest()


def constant_time_eq(a: bytes, b: bytes) -> bool:
    """Compare two byte strings without leaking where they differ."""
    return hmac.compare_digest(a, b)


def decode_secret(
    secret: str,
    *,
    strip_prefix: str | None,
    base64_encoded: bool | None,
) -> bytes:
    """Decode a caller-provided signing secret into raw HMAC key bytes.

    Args:
        secret: the secret exactly as configured by the caller.
        strip_prefix: provider-specific prefix to remove first (e.g.
            ``"whsec_"``), or ``None``.
        base64_encoded: ``True`` forces base64 decoding (raising
            :class:`ConfigurationError` on failure); ``False`` treats the
            value as raw UTF-8; ``None`` tries base64 first and falls back to
            raw UTF-8 (Standard Webhooks behaviour).

    Returns:
        Raw key bytes. Raises :class:`ConfigurationError` for empty or
        undecodable secrets. The secret value never appears in error text.
    """
    value = secret
    if strip_prefix and value.startswith(strip_prefix):
        value = value[len(strip_prefix) :]
    if not value:
        raise ConfigurationError("signing secret is empty after prefix stripping")
    if base64_encoded is False:
        return value.encode("utf-8")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        if base64_encoded is True:
            raise ConfigurationError("signing secret is not valid base64") from None
        return value.encode("utf-8")


def decode_signature(value: str, encoding: str, header: str) -> bytes:
    """Decode a signature value (``"hex"`` or ``"base64"``) into raw bytes.

    Raises :class:`InvalidHeaderFormatError` with a static reason string that
    never contains the rejected value.
    """
    if encoding == "hex":
        try:
            return bytes.fromhex(value)
        except ValueError:
            raise InvalidHeaderFormatError(header, "signature is not valid hex") from None
    if encoding == "base64":
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError):
            raise InvalidHeaderFormatError(header, "signature is not valid base64") from None
    raise ConfigurationError(f"unsupported signature encoding {encoding!r}")


def parse_timestamp(value: str, header: str) -> int:
    """Parse a Unix-seconds timestamp header value (ASCII digits only)."""
    if not value or not (value.isascii() and value.isdigit()):
        raise InvalidHeaderFormatError(header, "timestamp is not a non-negative integer")
    return int(value)

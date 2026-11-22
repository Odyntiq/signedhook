"""Encoding, decoding and constant-time comparison helpers.

Shared by every provider scheme so all of them behave identically on the
security-critical paths. None of these helpers log or embed secret material.
"""

from __future__ import annotations

import base64
import binascii
import hmac
from collections.abc import Sequence

from ._errors import ConfigurationError, InvalidHeaderFormatError

__all__ = [
    "SUPPORTED_DIGESTS",
    "SUPPORTED_TIMESTAMP_UNITS",
    "canonical_hmac",
    "canonical_hmac_sha256",
    "constant_time_eq",
    "decode_secret",
    "decode_signature",
    "normalize_secret_values",
    "parse_timestamp",
    "timestamp_to_seconds",
]

#: HMAC digest algorithms the shared pipeline accepts. HMAC-SHA1 remains
#: unbroken as a MAC construction and is required by real schemes (GitHub's
#: legacy header, Twilio); MD5 is deliberately excluded as cryptographically
#: deprecated and unused by mainstream webhook providers.
SUPPORTED_DIGESTS = ("sha1", "sha256", "sha384", "sha512")

#: Units a scheme's signed timestamp may use. ``"auto"`` detects
#: milliseconds by magnitude (see :data:`MILLISECONDS_THRESHOLD`).
SUPPORTED_TIMESTAMP_UNITS = ("seconds", "milliseconds", "auto")

#: Timestamps at or above this value are treated as milliseconds under the
#: ``"auto"`` unit: it equals Unix second 33658-08-19, so no legitimate
#: seconds timestamp reaches it, while every millisecond timestamp since
#: 2001-09-09 exceeds it.
MILLISECONDS_THRESHOLD = 10**12


def canonical_hmac(key: bytes, message: bytes, digest: str = "sha256") -> bytes:
    """Return the raw HMAC of ``message`` under ``key`` using ``digest``.

    Args:
        key: raw HMAC key bytes.
        message: the exact signed content.
        digest: one of :data:`SUPPORTED_DIGESTS` (``"sha1"``, ``"sha256"``,
            ``"sha384"``, ``"sha512"``). Other values raise
            :class:`ConfigurationError`.
    """
    if digest not in SUPPORTED_DIGESTS:
        raise ConfigurationError(
            f"unsupported digest {digest!r}; supported digests are: {', '.join(SUPPORTED_DIGESTS)}"
        )
    return hmac.new(key, message, digest).digest()


def canonical_hmac_sha256(key: bytes, message: bytes) -> bytes:
    """Return the raw HMAC-SHA256 digest of ``message`` under ``key``."""
    return canonical_hmac(key, message, "sha256")


def timestamp_to_seconds(value: int, unit: str = "seconds") -> int:
    """Normalise a signed timestamp to Unix seconds.

    ``"milliseconds"`` divides by 1000; ``"auto"`` applies magnitude
    detection (values >= :data:`MILLISECONDS_THRESHOLD` are milliseconds).
    The raw value is what schemes sign, so providers keep it for content
    reconstruction while this helper feeds tolerance checks and results.
    """
    if unit == "seconds":
        return value
    if unit == "milliseconds":
        return value // 1000
    if unit == "auto":
        return value // 1000 if value >= MILLISECONDS_THRESHOLD else value
    raise ConfigurationError(
        f"unsupported timestamp unit {unit!r}; supported units are: "
        f"{', '.join(SUPPORTED_TIMESTAMP_UNITS)}"
    )


def normalize_secret_values(secrets: str | Sequence[str]) -> tuple[str, ...]:
    """Normalise the ``secrets=`` argument into a validated string tuple.

    Accepts a single secret or an ordered sequence (rotation). Raises
    :class:`ConfigurationError` for an empty sequence and :class:`TypeError`
    for non-string members.
    """
    if isinstance(secrets, str):
        values: tuple[str, ...] = (secrets,)
    else:
        values = tuple(secrets)
    if not values:
        raise ConfigurationError("at least one signing secret is required")
    for value in values:
        if not isinstance(value, str):
            raise TypeError("signing secrets must be strings")
    return values


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

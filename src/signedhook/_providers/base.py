"""Provider scheme abstraction and shared verification machinery.

Every provider defines how to (a) detect its headers, (b) parse the signature
header into raw signature bytes plus a signed timestamp, (c) reconstruct the
exact signed content, and (d) decode secrets. The timing-sensitive HMAC
comparison lives here so all providers share one audited code path.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass

from .._encoding import canonical_hmac_sha256, constant_time_eq, decode_signature, parse_timestamp
from .._errors import (
    ConfigurationError,
    InvalidHeaderFormatError,
    MissingHeaderError,
    SignatureMismatchError,
    TimestampToleranceExceededError,
)
from .._types import VerificationResult

__all__ = ["HeaderMap", "ParsedSignature", "Provider"]

#: Lowercased header name -> value. Callers pass ordinary mappings; verify()
#: normalises the keys once, before any provider sees them.
HeaderMap = Mapping[str, str]


@dataclass(frozen=True, slots=True)
class ParsedSignature:
    """Provider-independent view of a parsed signature header set."""

    signatures: tuple[bytes, ...]
    timestamp: int | None
    message_key: str | None


class Provider(ABC):
    """A webhook signature scheme for one provider (or a family of them).

    Class attributes describe the scheme; subclasses override them. All
    attributes are also assignable per-instance, which is how
    :class:`~signedhook._providers.generic.GenericHMAC` builds configured
    schemes at runtime.
    """

    #: Registry name used by ``provider=`` arguments and results.
    name: str
    #: Signature scheme identifier reported in results.
    scheme: str = "hmac-sha256"
    #: Lowercase header names that must all be present for this scheme.
    required_headers: tuple[str, ...] = ()
    #: Lowercase header that carries the signature value.
    signature_header: str = ""
    #: Lowercase header that carries the Unix-seconds timestamp, if signed.
    timestamp_header: str | None = None

    @abstractmethod
    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        """Parse signature headers into raw signature bytes and metadata."""

    @abstractmethod
    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        """Reconstruct the exact byte string the provider signed."""

    @abstractmethod
    def secret_key(self, secret: str) -> bytes:
        """Decode one caller-provided secret into raw HMAC key bytes."""

    def detect(self, headers: HeaderMap) -> bool:
        """Return True when every header this scheme requires is present."""
        return all(header in headers for header in self.required_headers)

    def verify(
        self,
        payload: bytes,
        headers: HeaderMap,
        secret_keys: tuple[bytes, ...],
        *,
        now: int,
        tolerance: int | None,
    ) -> VerificationResult:
        """Run the full verification pipeline for this provider.

        Order of operations: parse headers (raising precise format errors),
        reject timestamps outside the tolerance window, then constant-time
        compare every provided signature against every secret. The first
        matching secret wins and its position is recorded for rotation
        bookkeeping.
        """
        parsed = self.parse_signature(headers)
        if parsed.timestamp is not None and tolerance is not None:
            delta = abs(now - parsed.timestamp)
            if delta > tolerance:
                raise TimestampToleranceExceededError(delta, tolerance)
        for position, key in enumerate(secret_keys):
            expected = canonical_hmac_sha256(key, self.signed_content(payload, headers, parsed))
            for provided in parsed.signatures:
                if constant_time_eq(expected, provided):
                    return VerificationResult(
                        provider=self.name,
                        scheme=self.scheme,
                        timestamp=parsed.timestamp,
                        matched_secret_index=position,
                        message_key=parsed.message_key,
                        payload_size=len(payload),
                    )
        raise SignatureMismatchError(self.name)


def _require(headers: HeaderMap, header: str) -> str:
    value = headers.get(header)
    if value is None:
        raise MissingHeaderError(header)
    return value


def _timestamp(headers: HeaderMap, header: str | None) -> int:
    if header is None:  # pragma: no cover - guarded by scheme definitions
        raise ConfigurationError("scheme declares no timestamp header")
    return parse_timestamp(_require(headers, header), header)


def _hex_signature(headers: HeaderMap, header: str, prefix: str) -> bytes:
    raw = _require(headers, header).strip()
    if not raw.startswith(prefix):
        raise InvalidHeaderFormatError(header, f"expected {prefix!r} prefix")
    return decode_signature(raw[len(prefix) :], "hex", header)


def _base64_signature(headers: HeaderMap, header: str, prefix: str) -> bytes:
    raw = _require(headers, header).strip()
    if prefix and not raw.startswith(prefix):
        raise InvalidHeaderFormatError(header, f"expected {prefix!r} prefix")
    return decode_signature(raw[len(prefix) :] if prefix else raw, "base64", header)

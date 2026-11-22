"""Generic configurable HMAC scheme for providers without a built-in adapter.

Many providers sign webhooks with a plain HMAC over a template of the
timestamp and payload. :class:`GenericHMAC` lets you describe such a scheme in
one object and register it, instead of hand-rolling verification code —
including SHA-1/SHA-256/SHA-384/SHA-512 digests, hex or base64 signatures and
second- or millisecond-based timestamps.
"""

from __future__ import annotations

from .._encoding import (
    SUPPORTED_DIGESTS,
    SUPPORTED_TIMESTAMP_UNITS,
    decode_secret,
    decode_signature,
    parse_timestamp,
)
from .._errors import ConfigurationError, InvalidHeaderFormatError, MissingHeaderError
from .base import HeaderMap, ParsedSignature, Provider

__all__ = ["GenericHMAC"]


class GenericHMAC(Provider):
    """A configurable HMAC signature scheme (any supported digest).

    Args:
        name: registry name to register this scheme under.
        sig_header: lowercase header carrying the signature.
        sig_prefix: literal prefix before the signature value (``""``,
            ``"sha256="``, ``"v0="`` ...).
        encoding: ``"hex"`` or ``"base64"``.
        secret_prefix: prefix stripped from secrets (``"whsec_"`` or ``None``).
        base64_secrets: ``True`` forces base64 secret decoding, ``False`` raw
            UTF-8, ``None`` tries base64 then raw.
        ts_header: lowercase header carrying the timestamp, or ``None`` when
            the scheme does not sign one.
        signed_template: format string with ``{ts}`` and/or ``{payload}``
            placeholders describing the signed byte string (e.g.
            ``"{ts}.{payload}"`` or ``"v0:{ts}:{payload}"``). Without a
            timestamp use ``"{payload}"``.
        message_key_header: optional header to surface as the replay key.
        digest: HMAC digest — ``"sha1"``, ``"sha256"``, ``"sha384"`` or
            ``"sha512"``; the reported scheme becomes ``hmac-<digest>``.
        ts_unit: unit of the timestamp header — ``"seconds"`` (default),
            ``"milliseconds"``, or ``"auto"`` (treat values >= 10^12 as
            milliseconds). The template always receives the raw signed value;
            tolerance checks and results are normalised to seconds.

    Example:
        >>> provider = GenericHMAC(
        ...     name="acme",
        ...     sig_header="x-acme-signature",
        ...     sig_prefix="sha256=",
        ...     ts_header="x-acme-timestamp",
        ...     signed_template="{ts}.{payload}",
        ... )
        >>> register_provider(provider)  # doctest: +SKIP

        A millisecond-timestamp, SHA-1, base64 scheme::

            GenericHMAC(
                name="legacy-vendor",
                sig_header="x-vendor-signature",
                encoding="base64",
                digest="sha1",
                ts_header="x-vendor-ts",
                signed_template="{ts}:{payload}",
                ts_unit="milliseconds",
            )
    """

    def __init__(
        self,
        name: str,
        sig_header: str,
        sig_prefix: str = "",
        encoding: str = "hex",
        secret_prefix: str | None = None,
        base64_secrets: bool | None = False,
        ts_header: str | None = None,
        signed_template: str = "{payload}",
        message_key_header: str | None = None,
        digest: str = "sha256",
        ts_unit: str = "seconds",
    ) -> None:
        if not name or not name.strip():
            raise ConfigurationError("GenericHMAC requires a non-empty registry name")
        if not sig_header or sig_header != sig_header.lower():
            raise ConfigurationError("sig_header must be a lowercase header name")
        if encoding not in ("hex", "base64"):
            raise ConfigurationError("encoding must be 'hex' or 'base64'")
        if digest not in SUPPORTED_DIGESTS:
            raise ConfigurationError(f"digest must be one of: {', '.join(SUPPORTED_DIGESTS)}")
        if ts_unit not in SUPPORTED_TIMESTAMP_UNITS:
            raise ConfigurationError(
                f"ts_unit must be one of: {', '.join(SUPPORTED_TIMESTAMP_UNITS)}"
            )
        if ts_header is not None and ts_header != ts_header.lower():
            raise ConfigurationError("ts_header must be a lowercase header name")
        if "{payload}" not in signed_template:
            raise ConfigurationError("signed_template must contain the {payload} placeholder")
        if ts_header is None and "{ts}" in signed_template:
            raise ConfigurationError("signed_template uses {ts} but no ts_header was configured")

        self.name = name.strip()
        self.scheme = f"hmac-{digest}"
        self.digest = digest
        self.timestamp_unit = ts_unit
        self.signature_header = sig_header
        self.timestamp_header = ts_header
        self._sig_prefix = sig_prefix
        self._encoding = encoding
        self._secret_prefix = secret_prefix
        self._base64_secrets = base64_secrets
        self._signed_template = signed_template
        self._message_key_header = message_key_header
        self.required_headers = (sig_header, ts_header) if ts_header is not None else (sig_header,)

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        raw = headers.get(self.signature_header)
        if raw is None:
            raise MissingHeaderError(self.signature_header)
        raw = raw.strip()
        prefix = self._sig_prefix
        if prefix:
            if not raw.startswith(prefix):
                raise InvalidHeaderFormatError(self.signature_header, f"expected {prefix!r} prefix")
            raw = raw[len(prefix) :]
        signature = decode_signature(raw, self._encoding, self.signature_header)

        timestamp: int | None = None
        if self.timestamp_header is not None:
            value = headers.get(self.timestamp_header)
            if value is None:
                raise MissingHeaderError(self.timestamp_header)
            timestamp = parse_timestamp(value, self.timestamp_header)

        message_key: str | None = None
        if self._message_key_header is not None:
            message_key = headers.get(self._message_key_header)

        return ParsedSignature(
            signatures=(signature,), timestamp=timestamp, message_key=message_key
        )

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        template = self._signed_template
        if "{ts}" in template:
            if parsed.timestamp is None:
                raise ConfigurationError("scheme signs a timestamp but none was parsed")
            template = template.replace("{ts}", str(parsed.timestamp))
        return _apply_template(template, payload)

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(
            secret, strip_prefix=self._secret_prefix, base64_encoded=self._base64_secrets
        )


def _apply_template(template: str, payload: bytes) -> bytes:
    """Apply ``{payload}`` substitution, returning raw signed bytes.

    The template is split on the literal ``{payload}`` marker so the payload
    bytes are inserted verbatim (never decoded or re-encoded).
    """
    before, sep, after = template.partition("{payload}")
    if not sep:
        raise ConfigurationError("signed_template must contain the {payload} placeholder")
    return before.encode("utf-8") + payload + after.encode("utf-8")

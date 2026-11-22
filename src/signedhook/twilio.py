"""Twilio webhook signature verification and signing.

Twilio's scheme (per its public "Secure your webhooks" documentation) differs
from every body-only provider: it signs the full request URL concatenated
with the POST parameters — sorted alphabetically by name, each key
immediately followed by its value — HMAC-SHA1'ed with the account auth token
and base64-encoded in the ``X-Twilio-Signature`` header.

Because the signed string includes the request URL, which is not part of the
body, Twilio has a dedicated entry point :func:`verify_twilio` instead of
``verify()``. The registry still contains a :class:`TwilioProvider` stub so
auto-detection and ``provider="twilio"`` fail with a precise, actionable
error instead of a generic "unrecognised headers" message.

Twilio signs no timestamp, so tolerance checks do not apply. For replay
protection pass ``replay_cache=``; the dedupe key defaults to a SHA-256 of
the signed string, stable for identical deliveries.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import logging
import urllib.parse
from collections.abc import Mapping, Sequence

from ._encoding import canonical_hmac, constant_time_eq, decode_secret, normalize_secret_values
from ._errors import (
    ConfigurationError,
    InvalidHeaderFormatError,
    MissingHeaderError,
    ReplayRejectedError,
    SignatureMismatchError,
)
from ._providers.base import HeaderMap, ParsedSignature, Provider
from ._types import VerificationResult
from .replay import ReplayCache

__all__ = [
    "TwilioProvider",
    "sign_twilio",
    "twilio_string_to_sign",
    "verify_twilio",
]

logger = logging.getLogger("signedhook.verify")

_SIGNATURE_HEADER = "x-twilio-signature"


class TwilioProvider(Provider):
    """Registry stub for Twilio; use :func:`verify_twilio` to verify.

    Twilio signs the request URL and form parameters rather than the raw
    body, so the body-only pipeline cannot reconstruct the signed content.
    This stub makes the scheme discoverable (``list_providers()``,
    auto-detection) and routes callers to the dedicated entry point with a
    precise error.
    """

    name = "twilio"
    scheme = "hmac-sha1"
    digest = "sha1"
    required_headers = (_SIGNATURE_HEADER,)
    signature_header = _SIGNATURE_HEADER
    timestamp_header = None

    def parse_signature(self, headers: HeaderMap) -> ParsedSignature:
        raw = headers.get(_SIGNATURE_HEADER)
        if raw is None:
            raise MissingHeaderError(_SIGNATURE_HEADER)
        signature = _decode_base64(raw.strip())
        return ParsedSignature(signatures=(signature,), timestamp=None, message_key=None)

    def signed_content(self, payload: bytes, headers: HeaderMap, parsed: ParsedSignature) -> bytes:
        raise ConfigurationError(
            "Twilio signs the request URL and form parameters, not the raw body; "
            "use signedhook.verify_twilio(url=..., params=..., headers=..., secrets=...)"
        )

    def secret_key(self, secret: str) -> bytes:
        return decode_secret(secret, strip_prefix=None, base64_encoded=False)


def twilio_string_to_sign(url: str, params: Mapping[str, str] | Sequence[tuple[str, str]]) -> str:
    """Build Twilio's string-to-sign: the URL plus sorted ``key+value`` pairs.

    Args:
        url: the full request URL exactly as Twilio delivered it (scheme,
            host, path and query string included).
        params: the POST parameters as a mapping or a sequence of pairs.
            Pairs may repeat a key; entries are sorted by (key, value), which
            matches Twilio's alphabetical parameter ordering.

    Raises:
        TypeError: ``url`` is not a ``str``, or any key/value is not a
            ``str``.
        ConfigurationError: ``url`` is empty.
    """
    if not isinstance(url, str):
        raise TypeError("url must be the full request URL as a string")
    if not url:
        raise ConfigurationError("url must be a non-empty request URL")
    if isinstance(params, Mapping):
        pairs = sorted(params.items())
    else:
        pairs = list(params)
        for name, value in pairs:
            if not isinstance(name, str) or not isinstance(value, str):
                raise TypeError("params keys and values must be strings")
        pairs.sort()
    return url + "".join(name + value for name, value in pairs)


def verify_twilio(
    url: str,
    params: Mapping[str, str] | Sequence[tuple[str, str]],
    headers: Mapping[str, str],
    *,
    secrets: str | Sequence[str],
    replay_cache: ReplayCache | None = None,
    key: str | None = None,
    ttl_seconds: float = 900,
) -> VerificationResult:
    """Verify a Twilio webhook request.

    Computes the string-to-sign from the request URL and POST parameters,
    then constant-time compares the ``X-Twilio-Signature`` header against
    every secret (ordered rotation, first match wins) using the shared HMAC
    pipeline — the same audited code path as ``verify()``.

    Args:
        url: the full request URL exactly as Twilio delivered it.
        params: the POST parameters (mapping or sequence of pairs; repeated
            keys allowed).
        headers: request headers; keys are matched case-insensitively.
        secrets: the Twilio auth token, or an ordered sequence for rotation.
        replay_cache: optional :class:`~signedhook.replay.ReplayCache`; when
            given, a delivery whose content was already accepted within
            ``ttl_seconds`` raises :class:`ReplayRejectedError`. Signature
            verification runs first, so unauthenticated traffic cannot
            poison the cache.
        key: explicit replay dedupe key; defaults to the SHA-256 hex digest
            of the string-to-sign (stable for identical deliveries).
        ttl_seconds: replay window for the cache entries.

    Returns:
        VerificationResult with ``provider="twilio"`` and
        ``scheme="hmac-sha1"``; ``payload_size`` is the byte length of the
        canonical form-encoded parameter body.

    Raises:
        TypeError: payload arguments of the wrong type.
        MissingHeaderError: ``X-Twilio-Signature`` is absent.
        InvalidHeaderFormatError: the signature is not valid base64.
        SignatureMismatchError: no secret produced a matching signature.
        ReplayRejectedError: the delivery was already accepted within the
            replay window.
        ConfigurationError: invalid secrets or an empty URL.
    """
    lowered = {str(name).lower(): value for name, value in headers.items()}
    raw = lowered.get(_SIGNATURE_HEADER)
    if raw is None:
        raise MissingHeaderError(_SIGNATURE_HEADER)
    provided = _decode_base64(raw.strip())

    string_to_sign = twilio_string_to_sign(url, params)
    content = string_to_sign.encode("utf-8")

    secret_values = normalize_secret_values(secrets)
    result: VerificationResult | None = None
    for position, value in enumerate(secret_values):
        token = decode_secret(value, strip_prefix=None, base64_encoded=False)
        expected = canonical_hmac(token, content, "sha1")
        if constant_time_eq(expected, provided):
            result = VerificationResult(
                provider="twilio",
                scheme="hmac-sha1",
                timestamp=None,
                matched_secret_index=position,
                message_key=None,
                payload_size=_form_encoded_size(params),
            )
            break

    if result is None:
        logger.debug(
            "webhook verification failed",
            extra={"provider": "twilio", "outcome": "failure", "reason_code": "signature_mismatch"},
        )
        raise SignatureMismatchError("twilio")

    if replay_cache is not None:
        dedupe_key = key or hashlib.sha256(content).hexdigest()
        if replay_cache.seen_within(dedupe_key, ttl_seconds):
            logger.debug(
                "webhook verification failed",
                extra={
                    "provider": "twilio",
                    "outcome": "failure",
                    "reason_code": "replay_rejected",
                },
            )
            raise ReplayRejectedError(dedupe_key)
        replay_cache.remember(dedupe_key, ttl_seconds)

    logger.debug(
        "webhook verified",
        extra={
            "provider": "twilio",
            "outcome": "success",
            "reason_code": "",
            "matched_secret_index": result.matched_secret_index,
        },
    )
    return result


def sign_twilio(
    url: str,
    params: Mapping[str, str] | Sequence[tuple[str, str]],
    *,
    secret: str,
) -> dict[str, str]:
    """Return Twilio signature headers for a request URL and parameters.

    Args:
        url: the full request URL the webhook will be delivered to.
        params: the POST parameters (mapping or sequence of pairs).
        secret: the Twilio auth token.

    Returns:
        A dict with the lowercase header ``x-twilio-signature`` ready to
        attach. The header value is safe to log.
    """
    token = decode_secret(secret, strip_prefix=None, base64_encoded=False)
    content = twilio_string_to_sign(url, params).encode("utf-8")
    signature = base64.b64encode(canonical_hmac(token, content, "sha1")).decode("ascii")
    return {"x-twilio-signature": signature}


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise InvalidHeaderFormatError(_SIGNATURE_HEADER, "signature is not valid base64") from None


def _form_encoded_size(params: Mapping[str, str] | Sequence[tuple[str, str]]) -> int:
    """Byte length of the canonical form-encoded parameter body."""
    pairs = sorted(params.items()) if isinstance(params, Mapping) else sorted(params)
    return len(urllib.parse.urlencode(pairs).encode("utf-8"))

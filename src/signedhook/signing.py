"""Sender-side signing (Standard Webhooks scheme).

Produce the exact headers a Standard Webhooks / Svix-compatible sender would
attach. Useful for testing receivers end-to-end, signing events from your
own services, and building provider-style webhook emitters.
"""

from __future__ import annotations

import base64
import time

from ._encoding import canonical_hmac_sha256, decode_secret
from ._errors import ConfigurationError

__all__ = ["sign"]


def sign(
    payload: bytes,
    *,
    secret: str,
    webhook_id: str,
    now: int | None = None,
    scheme: str = "standard",
) -> dict[str, str]:
    """Return Standard Webhooks headers signing ``payload``.

    Args:
        payload: raw body bytes to sign.
        secret: signing secret; ``whsec_``-prefixed base64 secrets and raw
            UTF-8 secrets are both accepted (same rules as verification).
        webhook_id: unique message id; becomes the receiver's replay key.
        now: Unix time in seconds (defaults to the current time).
        scheme: only ``"standard"`` is implemented.

    Returns:
        A dict with lowercase header names ready to attach:
        ``webhook-id``, ``webhook-timestamp``, ``webhook-signature``.
        The dict values are safe to log (no secret material).
    """
    if scheme != "standard":
        raise ConfigurationError(f"unsupported signing scheme {scheme!r}; only 'standard'")
    if not isinstance(payload, bytes):
        raise TypeError("payload must be raw bytes, not str")
    if not webhook_id:
        raise ConfigurationError("webhook_id must be a non-empty string")
    timestamp = int(time.time()) if now is None else now
    key = decode_secret(secret, strip_prefix="whsec_", base64_encoded=None)
    content = webhook_id.encode("utf-8") + b"." + str(timestamp).encode("ascii") + b"." + payload
    signature = base64.b64encode(canonical_hmac_sha256(key, content)).decode("ascii")
    return {
        "webhook-id": webhook_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": f"v1,{signature}",
    }

"""Public result types."""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["VerificationResult"]


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of a successful webhook verification.

    Attributes:
        provider: registry name of the provider scheme that matched
            (``"standard"``, ``"stripe"``, ``"github"``, ``"slack"``,
            ``"shopify"``, ``"razorpay"``, or a custom registration).
        scheme: signature scheme identifier (``"hmac-sha256"``).
        timestamp: the signed timestamp (Unix seconds) when the scheme signs
            one, otherwise ``None``.
        matched_secret_index: position in the caller's secret list of the
            secret that verified. Useful for rotation bookkeeping; never the
            secret itself.
        message_key: provider-supplied unique message identifier when the
            scheme carries one (e.g. the Standard Webhooks ``webhook-id``),
            else ``None``.
        payload_size: payload length in bytes.
    """

    provider: str
    scheme: str
    timestamp: int | None
    matched_secret_index: int
    message_key: str | None
    payload_size: int

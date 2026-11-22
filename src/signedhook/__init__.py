"""signedhook — verify signed webhooks from any provider with one call.

Zero-dependency, strictly-typed webhook signature verification for the
Standard Webhooks / Svix, Stripe, GitHub, Slack, Shopify and Razorpay
schemes, plus a configurable generic scheme. Auto-detection from headers,
secret rotation, tolerance windows, pluggable replay protection, a retry
scheduler for senders, sender-side signing, a CLI and an optional FastAPI
integration.

Quick start::

    from signedhook import verify

    result = verify(payload_bytes, request_headers, secrets=STRIPE_SECRET)
    # result.provider -> "stripe"
"""

from __future__ import annotations

from ._errors import (
    ConfigurationError,
    InvalidHeaderFormatError,
    MissingHeaderError,
    PayloadTooLargeError,
    ReplayRejectedError,
    SignatureMismatchError,
    SignedhookError,
    TimestampToleranceExceededError,
    UnknownProviderError,
)
from ._providers import (
    GenericHMAC,
    get_provider,
    list_providers,
    register_provider,
)
from ._settings import Settings
from ._types import VerificationResult
from .replay import MemoryReplayCache, ReplayCache
from .retry import RetryPolicy
from .signing import sign
from .verify import UNSET, verify, verify_with_replay

__version__ = "1.0.0"

__all__ = [
    "ConfigurationError",
    "GenericHMAC",
    "InvalidHeaderFormatError",
    "MemoryReplayCache",
    "MissingHeaderError",
    "PayloadTooLargeError",
    "ReplayCache",
    "ReplayRejectedError",
    "RetryPolicy",
    "Settings",
    "SignatureMismatchError",
    "SignedhookError",
    "TimestampToleranceExceededError",
    "UNSET",
    "UnknownProviderError",
    "VerificationResult",
    "__version__",
    "get_provider",
    "list_providers",
    "register_provider",
    "sign",
    "verify",
    "verify_with_replay",
]

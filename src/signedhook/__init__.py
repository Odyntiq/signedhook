"""signedhook — verify signed webhooks from any provider with one call.

Zero-dependency, strictly-typed webhook signature verification for the
Standard Webhooks / Svix, Stripe, GitHub (SHA-256 and legacy SHA-1), Slack,
Shopify, Razorpay and Twilio schemes, plus a configurable generic scheme
with any HMAC digest (SHA-1 / SHA-256 / SHA-384 / SHA-512), hex or base64
signatures and second- or millisecond-based timestamps. Auto-detection from
headers, secret rotation, tolerance windows, pluggable replay protection
(sync and async, in-memory / Redis / SQLite backends), incremental
streaming verification for very large bodies, a retry scheduler for
senders, sender-side signing, a CLI and optional FastAPI / Django / Flask
integrations.

Quick start::

    from signedhook import verify

    result = verify(payload_bytes, request_headers, secrets=STRIPE_SECRET)
    # result.provider -> "stripe"

Very large bodies can be verified while still streaming in::

    from signedhook import StreamingVerifier

    verifier = StreamingVerifier(headers, secrets=SECRET)
    for chunk in chunks:
        verifier.feed(chunk)
    result = verifier.finish()

Twilio signs the request URL and form parameters rather than the body, so
it has a dedicated entry point::

    from signedhook import verify_twilio

    result = verify_twilio(url, params, request_headers, secrets=AUTH_TOKEN)
    # result.provider -> "twilio"
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
from .replay import AsyncMemoryReplayCache, AsyncReplayCache, MemoryReplayCache, ReplayCache
from .replay_backends import (
    AsyncRedisReplayCache,
    AsyncSQLiteReplayCache,
    RedisReplayCache,
    SQLiteReplayCache,
)
from .retry import RetryPolicy
from .signing import sign
from .streaming import StreamingVerifier, verify_stream
from .twilio import sign_twilio, verify_twilio, verify_twilio_async
from .verify import UNSET, verify, verify_with_replay, verify_with_replay_async

__version__ = "1.3.0"

__all__ = [
    "AsyncMemoryReplayCache",
    "AsyncRedisReplayCache",
    "AsyncReplayCache",
    "AsyncSQLiteReplayCache",
    "ConfigurationError",
    "GenericHMAC",
    "InvalidHeaderFormatError",
    "MemoryReplayCache",
    "MissingHeaderError",
    "PayloadTooLargeError",
    "RedisReplayCache",
    "ReplayCache",
    "ReplayRejectedError",
    "RetryPolicy",
    "Settings",
    "SignatureMismatchError",
    "SignedhookError",
    "SQLiteReplayCache",
    "StreamingVerifier",
    "TimestampToleranceExceededError",
    "UNSET",
    "UnknownProviderError",
    "VerificationResult",
    "__version__",
    "get_provider",
    "list_providers",
    "register_provider",
    "sign",
    "sign_twilio",
    "verify",
    "verify_stream",
    "verify_twilio",
    "verify_twilio_async",
    "verify_with_replay",
    "verify_with_replay_async",
]

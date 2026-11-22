"""Shared HTTP error mapping for the framework integrations.

FastAPI, Django and Flask all translate verification failures into
structured HTTP responses with the same semantics: a machine-readable
``code`` field, the sanitised message, and a status resolved from this
single ordered table so behaviour cannot drift between integrations.
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

__all__ = ["resolve_status"]

#: Ordered (error type, HTTP status) defaults, evaluated top to bottom.
#: Subclasses listed earlier win, so keep the most specific types first.
DEFAULT_STATUS_MAP: tuple[tuple[type[SignedhookError], int], ...] = (
    (PayloadTooLargeError, 413),
    (MissingHeaderError, 400),
    (InvalidHeaderFormatError, 400),
    (ReplayRejectedError, 409),
    (SignatureMismatchError, 401),
    (TimestampToleranceExceededError, 401),
    (UnknownProviderError, 401),
    (ConfigurationError, 500),
)


def resolve_status(
    error: SignedhookError,
    overrides: dict[type[SignedhookError], int] | None = None,
) -> int:
    """Map a :class:`SignedhookError` to its default HTTP status.

    Args:
        error: the raised verification error.
        overrides: exact-type mapping that wins over the defaults
            (``{SignatureMismatchError: 403}``); ``None`` uses the defaults.

    Returns:
        The HTTP status code: 413 too large, 400 malformed, 401
        unauthenticated, 409 replayed, 500 misconfiguration.
    """
    error_type = type(error)
    if overrides and error_type in overrides:
        return overrides[error_type]
    for candidate, status in DEFAULT_STATUS_MAP:
        if isinstance(error, candidate):
            return status
    return 500

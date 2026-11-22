"""Exception hierarchy for signedhook.

Every exception carries a stable, machine-readable ``code`` so callers can
branch on error kinds without matching message strings. Messages never
contain secrets, signatures, or payload contents.
"""

from __future__ import annotations

__all__ = [
    "ConfigurationError",
    "InvalidHeaderFormatError",
    "MissingHeaderError",
    "PayloadTooLargeError",
    "ReplayRejectedError",
    "SignatureMismatchError",
    "SignedhookError",
    "TimestampToleranceExceededError",
    "UnknownProviderError",
]


class SignedhookError(Exception):
    """Base class for every error raised by signedhook."""

    code: str = "signedhook_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)


class ConfigurationError(SignedhookError):
    """Invalid configuration: malformed secret, bad tolerance, empty secret list."""

    code = "configuration_error"


class PayloadTooLargeError(SignedhookError):
    """The payload exceeds the configured size limit."""

    code = "payload_too_large"

    def __init__(self, size: int, limit: int) -> None:
        self.size = size
        self.limit = limit
        super().__init__(f"payload of {size} bytes exceeds the configured limit of {limit} bytes")


class MissingHeaderError(SignedhookError):
    """A signature header required by the provider scheme is absent."""

    code = "missing_header"

    def __init__(self, header: str) -> None:
        self.header = header
        super().__init__(f"required signature header {header!r} is missing")


class InvalidHeaderFormatError(SignedhookError):
    """A signature header is present but cannot be parsed."""

    code = "invalid_header_format"

    def __init__(self, header: str, reason: str) -> None:
        self.header = header
        self.reason = reason
        super().__init__(f"header {header!r} is malformed: {reason}")


class TimestampToleranceExceededError(SignedhookError):
    """The signed timestamp is outside the tolerated window."""

    code = "timestamp_outside_tolerance"

    def __init__(self, delta_seconds: int, limit_seconds: int) -> None:
        self.delta_seconds = delta_seconds
        self.limit_seconds = limit_seconds
        super().__init__(
            f"signed timestamp is {delta_seconds}s away from now, outside the "
            f"tolerance window of {limit_seconds}s"
        )


class SignatureMismatchError(SignedhookError):
    """No secret produced a signature matching the header value."""

    code = "signature_mismatch"

    def __init__(self, provider: str) -> None:
        self.provider = provider
        super().__init__(f"signature verification failed for provider {provider!r}")


class UnknownProviderError(SignedhookError):
    """The provider could not be determined, or the requested name is not registered."""

    code = "unknown_provider"

    def __init__(self, message: str, candidates: list[str] | None = None) -> None:
        self.candidates = list(candidates or [])
        super().__init__(message)


class ReplayRejectedError(SignedhookError):
    """A message with this dedupe key was already accepted (possible replay)."""

    code = "replay_rejected"

    def __init__(self, key_id: str) -> None:
        self.key_id = key_id[:64]
        super().__init__(f"message {self.key_id!r} was already accepted within the replay window")

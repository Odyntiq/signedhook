"""Library settings with environment-variable support."""

from __future__ import annotations

import os
from dataclasses import dataclass

from ._errors import ConfigurationError

__all__ = ["Settings"]

_MIN_TOLERANCE = 1
_MAX_TOLERANCE = 86_400
_MIN_MAX_PAYLOAD = 256
_MAX_MAX_PAYLOAD = 64 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class Settings:
    """Tunable limits applied to every verification call.

    Attributes:
        tolerance_seconds: default symmetric tolerance window (past and
            future, in seconds) for schemes that sign a timestamp; applies
            unless a call overrides it. ``None`` disables the check entirely
            (strongly discouraged).
        max_payload_bytes: reject payloads larger than this before doing any
            signature work — a cheap denial-of-service guard.
    """

    tolerance_seconds: int | None = 300
    max_payload_bytes: int = 2 * 1024 * 1024

    def __post_init__(self) -> None:
        tolerance = self.tolerance_seconds
        if tolerance is not None and not (_MIN_TOLERANCE <= tolerance <= _MAX_TOLERANCE):
            raise ConfigurationError(
                f"tolerance_seconds must be between {_MIN_TOLERANCE} and {_MAX_TOLERANCE}, or None"
            )
        if not (_MIN_MAX_PAYLOAD <= self.max_payload_bytes <= _MAX_MAX_PAYLOAD):
            raise ConfigurationError(
                f"max_payload_bytes must be between {_MIN_MAX_PAYLOAD} and {_MAX_MAX_PAYLOAD}"
            )

    @classmethod
    def from_env(cls, prefix: str = "VERIHOOK_") -> Settings:
        """Build settings from environment variables.

        Reads ``VERIHOOK_TOLERANCE_SECONDS`` and ``VERIHOOK_MAX_PAYLOAD_BYTES``
        (``prefix`` customisable). Unset variables keep the defaults; setting
        the tolerance variable to ``"none"`` (case-insensitive) disables the
        tolerance check. Invalid values raise :class:`ConfigurationError`.
        """
        tolerance_raw = os.environ.get(prefix + "TOLERANCE_SECONDS")
        payload_raw = os.environ.get(prefix + "MAX_PAYLOAD_BYTES")

        tolerance_set = tolerance_raw is not None
        payload_set = payload_raw is not None

        tolerance: int | None = cls._parse_tolerance(tolerance_raw, prefix)
        max_payload = cls._parse_payload(payload_raw, prefix)

        if tolerance_set and payload_set:
            return cls(tolerance_seconds=tolerance, max_payload_bytes=max_payload)
        if tolerance_set:
            return cls(tolerance_seconds=tolerance)
        if payload_set:
            return cls(max_payload_bytes=max_payload)
        return cls()

    @staticmethod
    def _parse_tolerance(raw: str | None, prefix: str) -> int | None:
        if raw is None:
            return None
        if raw.strip().lower() == "none":
            return None
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigurationError(f"{prefix}TOLERANCE_SECONDS is not an integer") from exc

    @staticmethod
    def _parse_payload(raw: str | None, prefix: str) -> int:
        if raw is None:
            return 2 * 1024 * 1024
        try:
            return int(raw)
        except ValueError as exc:
            raise ConfigurationError(f"{prefix}MAX_PAYLOAD_BYTES is not an integer") from exc

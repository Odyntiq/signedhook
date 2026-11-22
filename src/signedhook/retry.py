"""Retry scheduling for webhook senders.

Verifying received webhooks is only half of a trustworthy webhook pipeline;
senders must also deliver reliably. :class:`RetryPolicy` produces a
deterministic, jittered exponential-backoff schedule you can drive with any
HTTP client.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

__all__ = ["RetryPolicy"]


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Exponential backoff with jitter for outbound webhook deliveries.

    Attributes:
        max_attempts: total delivery attempts including the first.
        base_delay: delay before the first retry, in seconds.
        max_delay: cap for the unjittered delay.
        multiplier: growth factor applied after each attempt.
        jitter_ratio: symmetric jitter fraction (``0.2`` means each delay is
            perturbed by up to ±20%); capped at ``0.5``.
        seed: optional RNG seed for fully deterministic schedules (tests).

    Example:
        policy = RetryPolicy(max_attempts=5, base_delay=1.0)
        for delay in policy.delays():
            time.sleep(delay)
            deliver()  # stop when the receiver returns 2xx
    """

    max_attempts: int = 5
    base_delay: float = 1.0
    max_delay: float = 60.0
    multiplier: float = 2.0
    jitter_ratio: float = 0.2
    seed: int | None = None

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1")
        if self.base_delay <= 0:
            raise ValueError("base_delay must be positive")
        if self.max_delay < self.base_delay:
            raise ValueError("max_delay must be >= base_delay")
        if self.multiplier < 1.0:
            raise ValueError("multiplier must be >= 1.0")
        if not 0.0 <= self.jitter_ratio <= 0.5:
            raise ValueError("jitter_ratio must be between 0.0 and 0.5")

    def delays(self) -> list[float]:
        """Return the wait times between attempts (length ``max_attempts - 1``).

        Each delay is the capped exponential value perturbed by symmetric
        jitter, clamped to be non-negative.
        """
        rng = random.Random(self.seed)
        schedule: list[float] = []
        delay = self.base_delay
        for _ in range(self.max_attempts - 1):
            capped = min(delay, self.max_delay)
            jitter = capped * self.jitter_ratio
            perturbed = capped + rng.uniform(-jitter, jitter) if jitter else capped
            schedule.append(max(0.0, perturbed))
            delay = min(delay * self.multiplier, self.max_delay)
        return schedule

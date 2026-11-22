"""RetryPolicy schedule tests."""

from __future__ import annotations

import pytest

from signedhook import RetryPolicy


def test_no_retries_yields_empty_schedule() -> None:
    assert RetryPolicy(max_attempts=1).delays() == []


def test_schedule_length_is_attempts_minus_one() -> None:
    assert len(RetryPolicy(max_attempts=6).delays()) == 5


def test_exact_growth_and_cap_without_jitter() -> None:
    policy = RetryPolicy(
        max_attempts=5, base_delay=1.0, multiplier=2.0, max_delay=3.0, jitter_ratio=0.0
    )
    assert policy.delays() == [1.0, 2.0, 3.0, 3.0]


def test_seed_makes_schedule_deterministic() -> None:
    a = RetryPolicy(max_attempts=4, seed=1234).delays()
    b = RetryPolicy(max_attempts=4, seed=1234).delays()
    assert a == b


def test_jitter_stays_within_ratio() -> None:
    policy = RetryPolicy(max_attempts=6, base_delay=10.0, max_delay=10.0, jitter_ratio=0.2, seed=7)
    for delay in policy.delays():
        assert 8.0 <= delay <= 12.0


def test_zero_jitter_ratio_is_exact() -> None:
    policy = RetryPolicy(max_attempts=3, base_delay=2.0, multiplier=1.0, jitter_ratio=0.0, seed=1)
    assert policy.delays() == [2.0, 2.0]


def test_delays_never_negative() -> None:
    policy = RetryPolicy(max_attempts=6, base_delay=0.01, jitter_ratio=0.5, seed=3)
    assert all(delay >= 0.0 for delay in policy.delays())


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_attempts": 0},
        {"base_delay": 0},
        {"base_delay": -1},
        {"max_delay": 0.5, "base_delay": 1.0},
        {"multiplier": 0.5},
        {"jitter_ratio": 0.6},
        {"jitter_ratio": -0.1},
    ],
)
def test_invalid_policies_rejected(kwargs: dict[str, float]) -> None:
    with pytest.raises(ValueError):
        RetryPolicy(**kwargs)  # type: ignore[arg-type]

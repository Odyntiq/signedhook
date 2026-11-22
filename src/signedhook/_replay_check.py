"""Runtime duck-typing checks for replay-cache objects.

The replay caches are structural :class:`typing.Protocol` classes, which
cannot be used with ``isinstance`` (protocols without ``runtime_checkable``
raise ``TypeError``, and even decorated ones do not check signatures).
These helpers give the framework integrations a precise, dependency-free
way to accept either the sync or the async protocol at runtime.
"""

from __future__ import annotations

from inspect import iscoroutinefunction
from typing import Any

__all__ = ["is_async_replay_cache", "is_replay_cache"]


def is_replay_cache(obj: Any) -> bool:
    """Return True when ``obj`` structurally implements the sync protocol."""
    if callable(obj):  # factories / classes are not cache instances
        return False
    return callable(getattr(obj, "seen_within", None)) and callable(getattr(obj, "remember", None))


def is_async_replay_cache(obj: Any) -> bool:
    """Return True when ``obj`` structurally implements the async protocol."""
    if callable(obj):  # factories / classes are not cache instances
        return False
    seen = getattr(obj, "seen_within", None)
    remember = getattr(obj, "remember", None)
    return (
        seen is not None
        and remember is not None
        and iscoroutinefunction(seen)
        and iscoroutinefunction(remember)
    )

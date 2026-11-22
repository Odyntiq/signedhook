"""Provider registry: built-in schemes, auto-detection and custom registration."""

from __future__ import annotations

from .._errors import UnknownProviderError
from ..twilio import TwilioProvider
from .base import HeaderMap, Provider
from .generic import GenericHMAC
from .github import GitHubLegacyProvider, GitHubProvider
from .razorpay import RazorpayProvider
from .shopify import ShopifyProvider
from .slack import SlackProvider
from .standard import StandardWebhooksProvider
from .stripe import StripeProvider

__all__ = [
    "GenericHMAC",
    "GitHubLegacyProvider",
    "GitHubProvider",
    "RazorpayProvider",
    "ShopifyProvider",
    "SlackProvider",
    "StandardWebhooksProvider",
    "StripeProvider",
    "TwilioProvider",
    "detect_provider",
    "get_provider",
    "list_providers",
    "register_provider",
]

_BUILTIN_PROVIDERS: tuple[Provider, ...] = (
    StandardWebhooksProvider(),
    StripeProvider(),
    GitHubProvider(),
    GitHubLegacyProvider(),
    SlackProvider(),
    ShopifyProvider(),
    RazorpayProvider(),
    TwilioProvider(),
)

_REGISTRY: dict[str, Provider] = {provider.name: provider for provider in _BUILTIN_PROVIDERS}


def list_providers() -> list[str]:
    """Return the names of all registered provider schemes, sorted."""
    return sorted(_REGISTRY)


def get_provider(name: str) -> Provider:
    """Return the registered provider with this name.

    Raises :class:`UnknownProviderError` listing the known names otherwise.
    """
    provider = _REGISTRY.get(name)
    if provider is None:
        known = list_providers()
        raise UnknownProviderError(
            f"unknown provider {name!r}; registered providers are: {', '.join(known)}",
            candidates=known,
        )
    return provider


def register_provider(provider: Provider, *, replace: bool = False) -> None:
    """Register a custom provider scheme (e.g. a configured :class:`GenericHMAC`).

    Args:
        provider: the scheme instance to register.
        replace: allow replacing an existing registration of the same name.
    Raises:
        ConfigurationError when the name is already registered and ``replace``
        is False.
    """
    from .._errors import ConfigurationError

    if provider.name in _REGISTRY and not replace:
        raise ConfigurationError(
            f"provider {provider.name!r} is already registered; pass replace=True to override"
        )
    _REGISTRY[provider.name] = provider


def detect_provider(headers: HeaderMap) -> Provider:
    """Detect which registered scheme the headers belong to.

    Returns the unique scheme whose required headers are all present. Raises
    :class:`UnknownProviderError` when no scheme matches (listing known
    names) or when several match (listing the candidates).
    """
    candidates = [provider for provider in _REGISTRY.values() if provider.detect(headers)]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        known = ", ".join(list_providers())
        raise UnknownProviderError(
            "no recognised webhook signature headers; registered providers are: " + known
        )
    names = sorted(provider.name for provider in candidates)
    raise UnknownProviderError(
        "headers match multiple registered schemes; pass provider= explicitly", candidates=names
    )

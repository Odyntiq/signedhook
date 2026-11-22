"""Secret rotation and replay-protection behaviour."""

from __future__ import annotations

import threading

import pytest

from conftest import NOW, PAYLOAD, STD_ID, STD_SECRET_HEADER, std_headers
from signedhook import (
    ConfigurationError,
    MemoryReplayCache,
    ReplayRejectedError,
    SignatureMismatchError,
    verify,
    verify_with_replay,
)


class TestRotation:
    def test_first_matching_secret_wins(self) -> None:
        result = verify(
            PAYLOAD,
            std_headers(),
            secrets=[STD_SECRET_HEADER, "whsec_other", "whsec_another"],
            provider="standard",
            now=NOW,
        )
        assert result.matched_secret_index == 0

    def test_second_secret_reported_by_index(self) -> None:
        sig = std_headers()["webhook-signature"]
        with pytest.raises(SignatureMismatchError):
            # Signature is for the canonical secret; secrets list omits it.
            verify(
                PAYLOAD,
                std_headers(sig=sig),
                secrets=["whsec_a", "whsec_b"],
                provider="standard",
                now=NOW,
            )

    def test_rotation_across_two_valid_secrets(self) -> None:
        # New secret signs with same scheme; rotate list order determines index.
        old_key = b"old-key-00000000000000000000000000"
        import base64
        import hashlib
        import hmac

        content = f"{STD_ID}.{NOW}.".encode() + PAYLOAD
        old_sig = (
            "v1," + base64.b64encode(hmac.new(old_key, content, hashlib.sha256).digest()).decode()
        )
        old_secret = "whsec_" + base64.b64encode(old_key).decode()
        headers_new = std_headers()  # canonical secret signature
        headers_old = std_headers(sig=old_sig)
        result = verify(
            PAYLOAD,
            headers_old,
            secrets=[STD_SECRET_HEADER, old_secret],
            provider="standard",
            now=NOW,
        )
        assert result.matched_secret_index == 1
        result2 = verify(
            PAYLOAD,
            headers_new,
            secrets=[STD_SECRET_HEADER, old_secret],
            provider="standard",
            now=NOW,
        )
        assert result2.matched_secret_index == 0


class TestMemoryCache:
    def test_remember_then_seen(self) -> None:
        cache = MemoryReplayCache()
        assert not cache.seen_within("k1", ttl_seconds=60)
        cache.remember("k1", ttl_seconds=60)
        assert cache.seen_within("k1", ttl_seconds=60)
        assert not cache.seen_within("k2", ttl_seconds=60)

    def test_entries_expire(self) -> None:
        import time

        cache = MemoryReplayCache()
        cache.remember("k1", ttl_seconds=0.05)
        assert cache.seen_within("k1", ttl_seconds=10)
        time.sleep(0.08)
        assert not cache.seen_within("k1", ttl_seconds=10)

    def test_discard_and_clear(self) -> None:
        cache = MemoryReplayCache()
        cache.remember("k1", ttl_seconds=60)
        cache.discard("k1")
        assert not cache.seen_within("k1", ttl_seconds=60)
        cache.remember("k2", ttl_seconds=60)
        cache.clear()
        assert len(cache) == 0

    def test_concurrent_remember_is_safe(self) -> None:
        cache = MemoryReplayCache()
        threads = [threading.Thread(target=cache.remember, args=(f"k{i}", 60)) for i in range(16)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(cache) == 16


class TestVerifyWithReplay:
    def test_same_message_id_rejected_within_window(self) -> None:
        cache = MemoryReplayCache()
        kwargs = {"secrets": STD_SECRET_HEADER, "provider": "standard", "now": NOW}
        result = verify_with_replay(PAYLOAD, std_headers(), cache, **kwargs)
        assert result.message_key == STD_ID
        with pytest.raises(ReplayRejectedError) as excinfo:
            verify_with_replay(PAYLOAD, std_headers(), cache, **kwargs)
        assert excinfo.value.code == "replay_rejected"

    def test_different_message_id_accepted(self) -> None:
        from signedhook import sign

        cache = MemoryReplayCache()
        kwargs = {"secrets": STD_SECRET_HEADER, "provider": "standard", "now": NOW}
        verify_with_replay(PAYLOAD, std_headers(), cache, **kwargs)
        next_headers = sign(PAYLOAD, secret=STD_SECRET_HEADER, webhook_id="msg_next_1", now=NOW)
        verify_with_replay(PAYLOAD, next_headers, cache, **kwargs)
        assert len(cache) == 2

    def test_explicit_key_overrides(self) -> None:
        cache = MemoryReplayCache()
        kwargs = {"secrets": STD_SECRET_HEADER, "provider": "standard", "now": NOW}
        verify_with_replay(PAYLOAD, std_headers(), cache, key="order-1", **kwargs)
        # Same webhook id but different explicit key -> accepted.
        verify_with_replay(PAYLOAD, std_headers(), cache, key="order-2", **kwargs)

    def test_key_header_for_idless_schemes(self) -> None:
        cache = MemoryReplayCache()
        headers = {"x-hub-signature-256": None, "x-github-delivery": "uuid-1"}
        from conftest import GH_SECRET, GH_SIG

        headers["x-hub-signature-256"] = GH_SIG
        base = {"secrets": GH_SECRET, "provider": "github", "key_header": "x-github-delivery"}
        verify_with_replay(PAYLOAD, headers, cache, **base)
        with pytest.raises(ReplayRejectedError):
            verify_with_replay(PAYLOAD, headers, cache, **base)
        headers["x-github-delivery"] = "uuid-2"
        verify_with_replay(PAYLOAD, headers, cache, **base)

    def test_no_resolvable_key_is_a_configuration_error(self) -> None:
        from conftest import STRIPE_SECRET, STRIPE_SIG

        cache = MemoryReplayCache()
        with pytest.raises(ConfigurationError) as excinfo:
            verify_with_replay(
                PAYLOAD,
                {"stripe-signature": STRIPE_SIG},
                cache,
                secrets=STRIPE_SECRET,
                provider="stripe",
                now=NOW,
            )
        assert "replay key" in str(excinfo.value)

    def test_failed_verification_does_not_poison_cache(self) -> None:
        cache = MemoryReplayCache()
        with pytest.raises(SignatureMismatchError):
            verify_with_replay(
                b"tampered",
                std_headers(),
                cache,
                secrets=STD_SECRET_HEADER,
                provider="standard",
                now=NOW,
            )
        assert len(cache) == 0
        result = verify_with_replay(
            PAYLOAD,
            std_headers(),
            cache,
            secrets=STD_SECRET_HEADER,
            provider="standard",
            now=NOW,
        )
        assert result.provider == "standard"

    def test_ttl_expiry_allows_repeat(self) -> None:
        import time

        cache = MemoryReplayCache()
        kwargs = {
            "secrets": STD_SECRET_HEADER,
            "provider": "standard",
            "now": NOW,
            "ttl_seconds": 0.05,
        }
        verify_with_replay(PAYLOAD, std_headers(), cache, **kwargs)
        time.sleep(0.08)
        verify_with_replay(PAYLOAD, std_headers(), cache, **kwargs)

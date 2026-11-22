"""Streaming verification: incremental equivalence, guards and replay.

Every built-in body-signing scheme is verified twice from the same signed
request — once through ``verify()`` (whole-body path) and once through
``StreamingVerifier`` fed in chunks — and the results must be identical.
Vectors come from conftest (computed independently of the library).
"""

from __future__ import annotations

import pytest

from conftest import (
    GENERIC512_SIG_B64,
    GENERIC_PAYLOAD,
    GENERIC_SECRET,
    GH_LEGACY_PAYLOAD,
    GH_LEGACY_SECRET,
    GH_LEGACY_SIG,
    GH_SECRET,
    GH_SIG,
    MS_SECRET,
    MS_SIG,
    MS_TS,
    NOW,
    PAYLOAD,
    RAZORPAY_SECRET,
    RAZORPAY_SIG,
    SHOPIFY_SECRET,
    SHOPIFY_SIG,
    SLACK_SECRET,
    SLACK_SIG,
    STD_SECRET_HEADER,
    STRIPE_SECRET,
    STRIPE_SIG,
    hmac_sha256_hex,
    std_headers,
)
from signedhook import (
    ConfigurationError,
    GenericHMAC,
    MemoryReplayCache,
    PayloadTooLargeError,
    ReplayRejectedError,
    Settings,
    SignatureMismatchError,
    StreamingVerifier,
    TimestampToleranceExceededError,
    register_provider,
    verify,
    verify_stream,
)

SLACK_HEADERS = {"x-slack-signature": SLACK_SIG, "x-slack-request-timestamp": str(NOW)}
SHOPIFY_HEADERS = {"x-shopify-hmac-sha256": SHOPIFY_SIG}
RAZORPAY_HEADERS = {"x-razorpay-signature": RAZORPAY_SIG}
GH_HEADERS = {"x-hub-signature-256": GH_SIG}
GH_LEGACY_HEADERS = {"x-hub-signature": GH_LEGACY_SIG}
GENERIC_HEADERS = {"x-acme-sig": GENERIC512_SIG_B64}
MS_HEADERS = {"x-acme-sig": MS_SIG, "x-acme-ts": str(MS_TS)}

#: (label, payload, headers, secrets) for every built-in body-signing scheme.
SCHEMES: list[tuple[str, bytes, dict[str, str], str]] = [
    ("standard", PAYLOAD, std_headers(), STD_SECRET_HEADER),
    ("stripe", PAYLOAD, {"stripe-signature": STRIPE_SIG}, STRIPE_SECRET),
    ("slack", PAYLOAD, SLACK_HEADERS, SLACK_SECRET),
    ("shopify", PAYLOAD, SHOPIFY_HEADERS, SHOPIFY_SECRET),
    ("razorpay", PAYLOAD, RAZORPAY_HEADERS, RAZORPAY_SECRET),
    ("github", PAYLOAD, GH_HEADERS, GH_SECRET),
    ("github-legacy", GH_LEGACY_PAYLOAD, GH_LEGACY_HEADERS, GH_LEGACY_SECRET),
]


def chunks_of(data: bytes, size: int) -> list[bytes]:
    return [data[i : i + size] for i in range(0, len(data), size)]


@pytest.fixture(scope="module", autouse=True)
def _generic_providers() -> None:
    register_provider(
        GenericHMAC(
            name="acme512",
            sig_header="x-acme-sig",
            encoding="base64",
            digest="sha512",
            signed_template="{payload}",
        ),
        replace=True,
    )
    register_provider(
        GenericHMAC(
            name="acme-suffix",
            sig_header="x-sig",
            sig_prefix="v1=",
            ts_header="x-ts",
            signed_template="{payload}@{ts}",  # payload-first: exercises the suffix path
        ),
        replace=True,
    )


class TestEquivalence:
    """Streaming must be indistinguishable from the whole-body pipeline."""

    @pytest.mark.parametrize("label,payload,headers,secrets", SCHEMES)
    @pytest.mark.parametrize("chunk_size", [1, 3, 10_000])
    def test_chunked_result_matches_verify(
        self, label: str, payload: bytes, headers: dict[str, str], secrets: str, chunk_size: int
    ) -> None:
        expected = verify(payload, headers, secrets=secrets, now=NOW)
        result = verify_stream(chunks_of(payload, chunk_size), headers, secrets=secrets, now=NOW)
        assert result == expected

    def test_generic_sha512_scheme(self) -> None:
        expected = verify(
            GENERIC_PAYLOAD, GENERIC_HEADERS, secrets=GENERIC_SECRET, provider="acme512", now=1
        )
        result = verify_stream(
            chunks_of(GENERIC_PAYLOAD, 2),
            GENERIC_HEADERS,
            secrets=GENERIC_SECRET,
            provider="acme512",
            now=1,
        )
        assert result == expected

    def test_generic_suffix_template_scheme(self) -> None:
        # Signed content is "{payload}@{ts}" — the payload sits at the START,
        # so the streaming suffix must absorb "@{ts}" and the chunk split
        # must not change the outcome.
        ts = str(NOW)
        sig = "v1=" + hmac_sha256_hex(GENERIC_SECRET, GENERIC_PAYLOAD + f"@{ts}".encode("ascii"))
        headers = {"x-sig": sig, "x-ts": ts}
        expected = verify(
            GENERIC_PAYLOAD, headers, secrets=GENERIC_SECRET, provider="acme-suffix", now=NOW
        )
        result = verify_stream(
            chunks_of(GENERIC_PAYLOAD, 4),
            headers,
            secrets=GENERIC_SECRET,
            provider="acme-suffix",
            now=NOW,
        )
        assert result == expected
        assert result.scheme == "hmac-sha256"

    def test_millisecond_generic_scheme(self) -> None:
        register_provider(
            GenericHMAC(
                name="acme-ms",
                sig_header="x-acme-sig",
                sig_prefix="v1=",
                ts_header="x-acme-ts",
                signed_template="{ts}|{payload}",
                ts_unit="milliseconds",
            ),
            replace=True,
        )
        expected = verify(
            GENERIC_PAYLOAD,
            MS_HEADERS,
            secrets=MS_SECRET,
            provider="acme-ms",
            now=1_732_297_200 + 10,
        )
        result = verify_stream(
            chunks_of(GENERIC_PAYLOAD, 3),
            MS_HEADERS,
            secrets=MS_SECRET,
            provider="acme-ms",
            now=1_732_297_200 + 10,
        )
        assert result == expected

    def test_secret_rotation_reports_matched_index(self) -> None:
        headers = std_headers()
        expected = verify(PAYLOAD, headers, secrets=["wrong-secret", STD_SECRET_HEADER], now=NOW)
        assert expected.matched_secret_index == 1
        result = verify_stream(
            chunks_of(PAYLOAD, 5),
            headers,
            secrets=["wrong-secret", STD_SECRET_HEADER],
            now=NOW,
        )
        assert result.matched_secret_index == 1

    def test_bytes_input_behaves_like_verify(self) -> None:
        headers = {"x-hub-signature-256": GH_SIG}
        assert verify_stream(PAYLOAD, headers, secrets=GH_SECRET, now=NOW) == verify(
            PAYLOAD, headers, secrets=GH_SECRET, now=NOW
        )
        # bytearray and memoryview inputs are accepted as single chunks
        assert verify_stream(bytearray(PAYLOAD), headers, secrets=GH_SECRET, now=NOW) == verify(
            PAYLOAD, headers, secrets=GH_SECRET, now=NOW
        )
        assert verify_stream(memoryview(PAYLOAD), headers, secrets=GH_SECRET, now=NOW) == verify(
            PAYLOAD, headers, secrets=GH_SECRET, now=NOW
        )

    def test_empty_body_verifies(self) -> None:
        sig = "sha256=" + hmac_sha256_hex(GH_SECRET, b"")
        result = verify_stream(b"", {"x-hub-signature-256": sig}, secrets=GH_SECRET, now=NOW)
        assert result.payload_size == 0


class TestFailureModes:
    def test_bad_signature_raises_mismatch(self) -> None:
        verifier = StreamingVerifier(
            {"x-hub-signature-256": GH_SIG}, secrets="not-the-secret", now=NOW
        )
        verifier.feed(PAYLOAD)
        with pytest.raises(SignatureMismatchError):
            verifier.finish()

    def test_stale_timestamp_rejected_before_feeding(self) -> None:
        # Constructing the verifier with an out-of-window timestamp must
        # fail immediately, before any body byte is processed.
        with pytest.raises(TimestampToleranceExceededError):
            StreamingVerifier(std_headers(), secrets=STD_SECRET_HEADER, now=NOW + 10_000)

    def test_size_guard_aborts_mid_stream(self) -> None:
        settings = Settings(max_payload_bytes=300)  # minimum allowed
        big = b"x" * 400
        verifier = StreamingVerifier(
            {"x-hub-signature-256": GH_SIG}, secrets=GH_SECRET, settings=settings, now=NOW
        )
        with pytest.raises(PayloadTooLargeError) as excinfo:
            for chunk in chunks_of(big, 100):
                verifier.feed(chunk)
        assert excinfo.value.size > 300

    def test_size_guard_allows_exactly_the_limit(self) -> None:
        settings = Settings(max_payload_bytes=300)
        sig = "sha256=" + hmac_sha256_hex(GH_SECRET, b"x" * 300)
        result = verify_stream(
            chunks_of(b"x" * 300, 100),
            {"x-hub-signature-256": sig},
            secrets=GH_SECRET,
            settings=settings,
            now=NOW,
        )
        assert result.payload_size == 300

    def test_str_chunk_rejected(self) -> None:
        verifier = StreamingVerifier({"x-hub-signature-256": GH_SIG}, secrets=GH_SECRET, now=NOW)
        with pytest.raises(TypeError):
            verifier.feed('{"not":"bytes"}')

    def test_non_bytes_like_rejected(self) -> None:
        verifier = StreamingVerifier({"x-hub-signature-256": GH_SIG}, secrets=GH_SECRET, now=NOW)
        with pytest.raises(TypeError):
            verifier.feed([1, 2, 3])  # type: ignore[arg-type]

    def test_finish_twice_rejected(self) -> None:
        verifier = StreamingVerifier({"x-hub-signature-256": GH_SIG}, secrets=GH_SECRET, now=NOW)
        verifier.feed(PAYLOAD)
        verifier.finish()
        with pytest.raises(ConfigurationError):
            verifier.finish()

    def test_feed_after_finish_rejected(self) -> None:
        verifier = StreamingVerifier({"x-hub-signature-256": GH_SIG}, secrets=GH_SECRET, now=NOW)
        verifier.feed(PAYLOAD)
        verifier.finish()
        with pytest.raises(ConfigurationError):
            verifier.feed(b"more")

    def test_payload_size_tracks_fed_bytes(self) -> None:
        verifier = StreamingVerifier({"x-hub-signature-256": GH_SIG}, secrets=GH_SECRET, now=NOW)
        verifier.feed(b"abc")
        verifier.feed(b"de")
        assert verifier.payload_size == 5

    def test_twilio_rejected_with_actionable_error(self) -> None:
        with pytest.raises(ConfigurationError) as excinfo:
            StreamingVerifier(
                {"x-twilio-signature": "dGVzdA=="}, secrets="token", provider="twilio"
            )
        assert "twilio" in str(excinfo.value).lower()


class TestStreamingReplay:
    def test_verified_stream_populates_cache(self) -> None:
        cache = MemoryReplayCache()
        kwargs = {
            "replay_cache": cache,
            "secrets": STD_SECRET_HEADER,
            "now": NOW,
        }
        first = verify_stream(chunks_of(PAYLOAD, 7), std_headers(), **kwargs)
        assert first.provider == "standard"
        assert len(cache) == 1
        with pytest.raises(ReplayRejectedError):
            verify_stream(chunks_of(PAYLOAD, 3), std_headers(), **kwargs)

    def test_key_header_resolution(self) -> None:
        cache = MemoryReplayCache()
        headers = {**GH_HEADERS, "x-github-delivery": "delivery-42"}
        result = verify_stream(
            chunks_of(PAYLOAD, 9),
            headers,
            secrets=GH_SECRET,
            replay_cache=cache,
            key_header="x-github-delivery",
            now=NOW,
        )
        assert result.provider == "github"
        assert cache.seen_within("delivery-42", 900)

    def test_unverified_stream_never_touches_cache(self) -> None:
        cache = MemoryReplayCache()
        with pytest.raises(SignatureMismatchError):
            verify_stream(
                chunks_of(PAYLOAD, 4),
                std_headers(),
                secrets="wrong-secret",
                replay_cache=cache,
                now=NOW,
            )
        assert len(cache) == 0

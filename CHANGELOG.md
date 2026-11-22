# Changelog

All notable changes to signedhook are documented here. The format follows
Keep a Changelog; versioning follows Semantic Versioning.

## [1.2.0] — 2026-11-23

Framework integrations, async replay protection and streaming verification —
the full 1.0.0 roadmap, delivered.

### Added

- **Streaming verification** — `StreamingVerifier` and `verify_stream()`
  verify body-signed webhooks incrementally, chunk by chunk. Every built-in
  body scheme decomposes its signed content into `(prefix, payload, suffix)`
  via the new `Provider.streaming_parts()` hook, so the per-secret HMAC
  states are primed from headers alone, updated per chunk and finalised at
  body end. The payload-size limit is enforced *during* feeding (oversized
  deliveries abort mid-stream instead of after full buffering) and stale
  timestamps are rejected at construction, before any body byte is read.
  Equivalent to `verify()` by construction; equivalence is pinned by tests
  comparing both paths for every scheme at multiple chunk boundaries.
- **Async replay protection** — `AsyncReplayCache` protocol,
  `verify_with_replay_async()` and `verify_twilio_async()`. Signature
  verification stays synchronous (pure CPU); only the two cache operations
  are awaited, so async stores never block the event loop. Verify-first
  ordering preserved: unauthenticated traffic never touches the cache.
- **Async shared backends** — `AsyncRedisReplayCache` (any client with
  async `set`/`get`/`delete`, e.g. `redis.asyncio`) and
  `AsyncSQLiteReplayCache` (via `await AsyncSQLiteReplayCache.connect(path)`
  with the `signedhook[aiosqlite]` extra; same WAL schema as the sync twin).
  `AsyncMemoryReplayCache` wraps the thread-safe in-memory cache for
  single-process asyncio apps and can share state with sync code.
- **FastAPI: async caches** — `webhook_dependency(replay_cache=...)` now
  accepts an `AsyncReplayCache`; async caches are detected and awaited
  automatically.
- **Flask integration** (`signedhook[flask]`) — the `verify_webhook()`
  view decorator reads the raw body, verifies, injects the
  `VerificationResult` into the view and returns structured JSON errors
  (`{"detail": {"code", "message"}}`) with the shared status mapping.
- **Django integration** (`signedhook[django]`) — `WebhookMiddleware`
  verifies the routes declared in `settings.SIGNEDHOOK_ROUTES` before the
  view runs, attaches `request.signedhook_result`, disables the CSRF check
  for verified deliveries, and returns the same structured JSON errors.
  Per-route options: `provider`, `secrets` (with `env:NAME` resolution at
  startup), `tolerance`, `max_payload_bytes`, `replay` /
  `replay_cache` (instance or factory), `key_header`, `ttl_seconds`;
  unknown options and missing environment variables fail fast at boot.
- Shared HTTP error mapping (`_http.resolve_status`) used by all three
  integrations, so statuses cannot drift between frameworks.

### Changed

- `Provider` gained a concrete `streaming_parts()` default that rejects
  schemes whose signed content cannot be decomposed (Twilio) with a precise
  error. Existing custom providers are unaffected.

## [1.1.0] — 2026-11-22

Provider coverage and multi-worker replay protection.

### Added

- **Twilio scheme** — `verify_twilio(url, params, headers, secrets=...)` and
  `sign_twilio(...)`. Twilio signs the request URL plus alphabetically sorted
  POST parameters (HMAC-SHA1, base64) instead of the raw body, so it gets a
  dedicated entry point; the registry stub makes `provider="twilio"` and
  auto-detection fail with a precise, actionable error. Built-in replay
  support with a content-stable dedupe key (SHA-256 of the string-to-sign).
- **Legacy GitHub SHA-1 scheme** — `provider="github-legacy"` verifies the
  `X-Hub-Signature: sha1=...` header. Auto-detection prefers the SHA-256
  scheme whenever both headers are present; the legacy provider only matches
  when the modern header is absent.
- **Configurable digests** — `GenericHMAC(..., digest=...)` accepts
  `sha1`, `sha256`, `sha384` and `sha512` (`sha256` remains the default);
  the reported scheme string becomes `hmac-<digest>`. MD5 stays excluded as
  cryptographically deprecated.
- **Millisecond timestamps** — `GenericHMAC(..., ts_unit=...)` accepts
  `seconds` (default), `milliseconds` and `auto` (values >= 10^12 are
  treated as milliseconds). The signed template always receives the raw
  value; tolerance checks and `VerificationResult.timestamp` are normalised
  to seconds.
- **Shared replay caches for multi-worker deployments** —
  `RedisReplayCache(client, namespace=...)` works with any Redis-compatible
  client (one atomic command per operation; `pip install signedhook[redis]`)
  and `SQLiteReplayCache(path, namespace=...)` is the stdlib-only single-host
  option (WAL mode, per-worker connections, lazy pruning). Both implement
  the `ReplayCache` protocol and drop into `verify_with_replay` /
  `verify_twilio` unchanged.
- `twilio_string_to_sign(url, params)` helper exposing Twilio's canonical
  string construction.

### Changed

- The shared HMAC pipeline is digest-parameterised
  (`_encoding.canonical_hmac`); every built-in provider now reports its
  digest via `Provider.digest` and its scheme as `hmac-<digest>` where
  applicable. No behaviour change for existing callers.

## [1.0.0] — 2026-11-22

Initial release.

### Added

- `verify()` — single-call webhook verification with provider
  auto-detection from headers and strict per-provider mode.
- Built-in provider schemes: Standard Webhooks / Svix (`standard`), Stripe,
  GitHub, Slack, Shopify, Razorpay — all HMAC-SHA256, constant-time
  comparison, one shared audited code path.
- `GenericHMAC` — configurable scheme (header names, signature prefix,
  hex/base64 encoding, secret prefix, signed-content template, message-key
  header) with registry registration.
- Secret rotation via ordered secret lists; `VerificationResult.
  matched_secret_index` reports the winner.
- Timestamp tolerance windows (symmetric, default 300s, `Settings`
  controlled, per-call override, explicit disable).
- Replay protection: `ReplayCache` protocol, thread-safe
  `MemoryReplayCache`, `verify_with_replay()` with key resolution
  (explicit key → key header → scheme message id) and verify-first
  cache population.
- Sender side: `sign()` for Standard Webhooks headers and `RetryPolicy`
  with jittered exponential backoff.
- Optional FastAPI integration (`signedhook[fastapi]`) with structured
  HTTP error mapping (400/401/409/413) and status overrides.
- CLI: `signedhook providers | sign | verify` (JSON output mode, stable
  exit codes, `python -m signedhook` entry point).
- `Settings` with `VERIHOOK_*` environment support.
- Structured DEBUG logging on the `signedhook.verify` logger with secret
  hygiene asserted by tests.
- Full typing (`py.typed`, mypy `--strict` clean), zero runtime
  dependencies in the core, CI on Python 3.10–3.13.

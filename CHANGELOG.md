# Changelog

All notable changes to signedhook are documented here. The format follows
Keep a Changelog; versioning follows Semantic Versioning.

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

# Changelog

All notable changes to signedhook are documented here. The format follows
Keep a Changelog; versioning follows Semantic Versioning.

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

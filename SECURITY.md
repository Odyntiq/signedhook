# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.0.x | yes |

## Reporting a vulnerability

Report privately via GitHub's "Report a vulnerability" feature on
https://github.com/Odyntiq/signedhook (Security tab), or contact the
maintainers listed in CONTRIBUTORS.md. Do not open public issues or PRs for
vulnerability reports.

Include: affected version, environment, minimal reproduction, impact
assessment. You will receive an acknowledgement within 72 hours and a
remediation plan within 7 days. Coordinated disclosure is expected; we will
credit reporters who wish to be named.

## Security design notes

- **Constant-time comparison** — every signature comparison goes through
  `hmac.compare_digest` in a single shared code path.
- **Raw-bytes contract** — verification requires the raw `bytes` body;
  re-encoded strings are rejected because they invalidate signatures.
- **Tolerance windows** — signed timestamps are checked symmetrically
  (default ±300s) before any HMAC comparison, rejecting stale and future
  messages cheaply.
- **Replay defense** — message-id dedupe is available via the `ReplayCache`
  protocol; caches are populated only by *verified* messages so unverified
  traffic cannot poison them.
- **Secret hygiene** — secrets are decoded in-memory only; they never appear
  in error messages, logs, results, or CLI output. The bundled test suite
  asserts this hygiene.
- **Size limits** — payloads above `Settings.max_payload_bytes` are rejected
  before signature work (denial-of-service guard).
- **No dynamic code, no network I/O** — the core never evaluates code or
  makes network calls; the only optional runtime dependency is fastapi in
  the `signedhook[fastapi]` extra.

## Scope

The library verifies signatures; it does not manage endpoint
authentication, TLS, or idempotency of business side effects. Combine
signedhook with TLS termination checks and idempotent handlers for a
complete receiving pipeline.

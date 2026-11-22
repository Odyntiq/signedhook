# signedhook

**Verify signed webhooks from any provider with one call.**

`signedhook` is a zero-dependency Python library that verifies webhook
signature headers for the schemes used by Standard Webhooks / Svix, Stripe,
GitHub (SHA-256 and legacy SHA-1), Slack, Shopify, Razorpay and Twilio —
plus a configurable generic scheme (any HMAC digest, second- or
millisecond-based timestamps) for everyone else. Auto-detection, secret
rotation, timestamp tolerance windows, pluggable replay protection
(in-memory, Redis and SQLite backends), a retry scheduler for senders and
an optional FastAPI integration are built in. The core has no third-party
dependencies and is fully typed (`py.typed`, mypy `--strict` clean).

## The problem

Receiving webhooks securely means hand-assembling HMAC verification code for
each provider's quirky header format — and getting it wrong is the norm:

- GitHub signs the raw body only, Slack signs `v0:{timestamp}:{body}`,
  Stripe signs `{timestamp}.{body}` with comma-separated components,
  Standard Webhooks signs `{id}.{timestamp}.{body}` with base64 secrets,
  Twilio signs the request URL plus sorted form parameters with HMAC-SHA1.
- Timestamp tolerance (replay defense) is documented but rarely implemented.
- Secret rotation is almost never handled, so key changes break receivers.
- Snippets copied from docs compare signatures with `==`, use the wrong
  encoding, or verify against re-encoded JSON bodies.

Existing solutions are per-provider SDKs (heavy, one provider each), the
Standard Webhooks reference libs (one spec only), or full webhook *sending*
services (svix) that still delegate receiving to you. Fresh entrants cover
the JavaScript ecosystem — Python had no multi-provider equivalent.

`signedhook` closes that gap: **one audited HMAC code path, provider
adapters on top**.

## Key features

- **Multi-provider verification** — `standard`, `stripe`, `github`,
  `github-legacy`, `slack`, `shopify`, `razorpay` and `twilio`, plus
  `GenericHMAC` for custom schemes.
- **Auto-detection** — headers decide the scheme; strict mode also available.
- **Secret rotation** — pass an ordered secret list; the first secret that
  verifies wins and its index is reported.
- **Replay defense** — timestamp tolerance windows (default 300s, symmetric)
  plus a `ReplayCache` protocol for message-id dedupe, with thread-safe
  in-memory, Redis and SQLite backends bundled.
- **Sender-side signing** — `sign()` produces Standard Webhooks headers for
  round-trip testing and your own emitters.
- **Retry scheduler** — `RetryPolicy` gives jittered exponential backoff for
  outbound deliveries.
- **Precise, safe errors** — stable machine-readable `code` attributes;
  messages never contain secrets, signatures or payload contents.
- **Optional FastAPI integration** — a dependency factory that turns
  verification failures into structured HTTP errors (400/401/409/413).
- **CLI** — `signedhook providers | sign | verify` for debugging and CI.
- **Quality gates** — pytest (234 tests), ruff, mypy `--strict`, pip-audit,
  CI on Python 3.10–3.13.

## Provider support matrix

| Provider | Scheme name | Signature header | Signed content | Secret format | Timestamp |
|---|---|---|---|---|---|
| Standard Webhooks / Svix | `standard` | `webhook-signature` | `{id}.{ts}.{payload}` | `whsec_` + base64 (raw fallback) | yes |
| Stripe | `stripe` | `stripe-signature` | `{ts}.{payload}` | `whsec_` prefix stripped | yes |
| GitHub | `github` | `x-hub-signature-256` | `{payload}` | raw UTF-8 | no |
| GitHub (legacy) | `github-legacy` | `x-hub-signature` | `{payload}` | raw UTF-8 | no |
| Slack | `slack` | `x-slack-signature` | `v0:{ts}:{payload}` | raw UTF-8 | yes |
| Shopify | `shopify` | `x-shopify-hmac-sha256` | `{payload}` | raw UTF-8 | no |
| Razorpay | `razorpay` | `x-razorpay-signature` | `{payload}` | raw UTF-8 | no |
| Twilio | `twilio` | `x-twilio-signature` | `{url}` + sorted `key+value` params | raw auth token | no |
| Custom | registered `GenericHMAC` | configurable | configurable template | configurable | optional |

Built-in schemes use HMAC-SHA256 except GitHub legacy and Twilio (HMAC-SHA1,
per those providers' published schemes); `GenericHMAC` additionally offers
SHA-384 and SHA-512. Signatures are always compared in constant time.

## Architecture

```
payload + headers
        |
   verify()  ----------------- size guard, header normalisation
        |
  provider resolution ---- auto-detect (headers) or strict (name)
        |
  Provider.verify()  ------ parse headers -> tolerance check ->
        |                    HMAC-SHA256 per secret -> constant-time compare
        |
VerificationResult ------- provider, timestamp, matched secret index,
                            message key, payload size
```

Modules: `verify` (entry point), `_providers/*` (schemes + registry),
`_encoding` (decode/compare helpers), `replay` (cache protocol),
`replay_backends` (Redis / SQLite shared caches), `twilio` (URL + params
scheme), `retry` (sender backoff), `signing` (sender side), `fastapi`
(optional integration), `cli` (shell interface), `_settings` (limits, env
support).

## Installation

```bash
pip install signedhook

# with the FastAPI integration
pip install signedhook[fastapi]

# with the Redis replay backend (SQLite is stdlib-only, no extra needed)
pip install signedhook[redis]
```

Python 3.10+. No dependencies required for the core.

## Quick start

### Verify any webhook (auto-detection)

```python
from signedhook import verify


def handle_webhook(payload: bytes, headers: dict[str, str]) -> None:
    result = verify(payload, headers, secrets=STRIPE_WEBHOOK_SECRET)
    print(result.provider)  # "stripe"
    # ... process the payload
```

`verify` accepts a raw `bytes` body exactly as received and a mapping of
headers (any casing). It raises a typed `SignedhookError` subclass on every
failure mode — catch `SignedhookError` for a coarse handler or specific
classes for fine-grained ones.

### Strict mode per endpoint

```python
from signedhook import verify

result = verify(
    payload,
    headers,
    secrets=[new_secret, old_secret],  # rotation: old key keeps working
    provider="standard",  # or "stripe" / "github" / ...
    tolerance=300,  # seconds; None disables
)
```

### Twilio (URL + form parameters)

Twilio signs the request URL concatenated with the sorted POST parameters,
not the raw body, so it has a dedicated entry point:

```python
from signedhook import verify_twilio

result = verify_twilio(
    request_url,  # exactly as Twilio delivered it
    form_params,  # dict or list of pairs
    headers,
    secrets=TWILIO_AUTH_TOKEN,
)
print(result.provider)  # "twilio"
```

Pass `replay_cache=` for dedupe; the key defaults to a SHA-256 of the
string-to-sign, stable for identical deliveries.

### FastAPI receiver

```python
from fastapi import Depends, FastAPI
from signedhook import MemoryReplayCache, webhook_dependency

app = FastAPI()
verify_hook = webhook_dependency(
    provider="standard",
    secrets=WHSEC,
    replay_cache=MemoryReplayCache(),
)


@app.post("/webhooks/svix")
async def svix_events(result=Depends(verify_hook)) -> dict:
    return {"verified_provider": result.provider}
```

Failures become structured HTTP errors:
`{"detail": {"code": "signature_mismatch", "message": ...}}` with status
400 (malformed), 401 (unauthenticated), 409 (replayed), 413 (too large).

A runnable example lives in [`examples/fastapi_receiver.py`](examples/fastapi_receiver.py).

### CLI

```bash
# list provider schemes
signedhook providers

# produce Standard Webhooks headers (receiver testing)
signedhook sign --secret whsec_... --id msg_1 --json < body.json

# verify a request
signedhook verify --provider auto --secret whsec_... \
  --header "webhook-id: msg_1" \
  --header "webhook-timestamp: 1700000000" \
  --header "webhook-signature: v1,..." \
  --json < body.json
```

Exit codes: `0` verified, `1` verification failed (code reported), `2`
usage/config error. `python -m signedhook` works too.

## Configuration

`Settings` controls the global limits (defaults shown):

```python
from signedhook import Settings

settings = Settings(tolerance_seconds=300, max_payload_bytes=2 * 1024 * 1024)
verify(payload, headers, secrets=secret, settings=settings)
```

Environment support (used automatically by the CLI):

- `VERIHOOK_TOLERANCE_SECONDS` — integer, or `none` to disable the check.
- `VERIHOOK_MAX_PAYLOAD_BYTES` — integer.

## Replay protection in depth

Tolerance windows reject *old* messages; a replay cache additionally rejects
*resends inside the window*:

```python
from signedhook import MemoryReplayCache, verify_with_replay

cache = MemoryReplayCache()
result = verify_with_replay(
    payload,
    headers,
    cache,
    secrets=WHSEC,  # standard: keyed by webhook-id
    key_header="x-github-delivery",  # github: provider's delivery id
    ttl_seconds=900,
)
```

Key resolution order: explicit `key=` → `key_header` value → the scheme's
own message id (`webhook-id` for Standard Webhooks). Signature verification
runs **first** — only verified messages consume cache entries, so
unauthenticated traffic cannot poison the cache.

`MemoryReplayCache` is process-local. For multi-worker deployments two
shared backends ship in the box:

```python
from signedhook import RedisReplayCache, SQLiteReplayCache, verify_with_replay

# any Redis-compatible client (redis-py, Valkey, KeyDB): atomic per operation
cache = RedisReplayCache(redis_client, namespace="myapp:replay")

# stdlib-only, single host: pass the same path in every worker
cache = SQLiteReplayCache("/var/lib/myapp/replay.sqlite3")

result = verify_with_replay(payload, headers, cache, secrets=WHSEC)
```

`RedisReplayCache` needs any Redis-compatible client
(`pip install signedhook[redis]`); each operation is a single atomic Redis
command, so racing workers stay consistent. `SQLiteReplayCache` uses WAL
mode with a busy timeout and needs no server — ideal for gunicorn/uvicorn
workers on one machine. Or implement the two-method `ReplayCache` protocol
against your own database.

## API overview

| Call | Purpose |
|---|---|
| `verify(payload, headers, *, secrets, provider="auto", tolerance=UNSET, now=None, settings=None)` | Verify a webhook; raises typed errors |
| `verify_with_replay(..., cache, key=None, key_header=None, ttl_seconds=900)` | Verify + dedupe |
| `verify_twilio(url, params, headers, *, secrets, replay_cache=None, key=None, ttl_seconds=900)` | Verify Twilio (URL + params scheme) |
| `sign(payload, *, secret, webhook_id, now=None, scheme="standard")` | Produce sender headers |
| `sign_twilio(url, params, *, secret)` | Produce Twilio signature headers |
| `RetryPolicy(...).delays()` | Jittered backoff schedule |
| `list_providers()` / `get_provider(name)` / `register_provider(provider)` | Registry |
| `GenericHMAC(name, sig_header, sig_prefix, encoding, secret_prefix, base64_secrets, ts_header, signed_template, message_key_header, digest, ts_unit)` | Custom schemes (any digest, seconds/milliseconds) |
| `MemoryReplayCache` / `RedisReplayCache` / `SQLiteReplayCache` | Replay caches (process-local / Redis / SQLite) |
| `webhook_dependency(...)` (`signedhook.fastapi`) | FastAPI dependency factory |

Errors (all subclasses of `SignedhookError`, each with a stable `.code`):
`ConfigurationError`, `PayloadTooLargeError`, `MissingHeaderError`,
`InvalidHeaderFormatError`, `TimestampToleranceExceededError`,
`SignatureMismatchError`, `UnknownProviderError`, `ReplayRejectedError`.

Logging: the `signedhook.verify` logger emits DEBUG records with structured
fields (`provider`, `outcome`, `reason_code`) — never header values,
signatures, secrets or payloads.

## Testing

```bash
pip install -e ".[dev]"
pytest              # 234 tests
ruff check .
ruff format --check .
mypy                # --strict, src only
pip-audit
python -m build     # wheel + sdist
```

The provider test vectors are computed independently of the library from the
public scheme definitions, so tests validate scheme constants rather than
the implementation mirroring itself.

## Security considerations

- Signatures are compared with `hmac.compare_digest` (constant time).
- The payload is processed as raw bytes; `str` inputs are rejected because
  re-encoding invalidates signatures (a common middleware bug).
- Size limits are enforced before any HMAC work (cheap DoS guard).
- Timestamp tolerance is symmetric (past *and* future), default 5 minutes,
  matching the 2026 ecosystem consensus.
- HMAC-SHA1 appears only where the provider's published scheme requires it
  (GitHub legacy, Twilio); it is sound as a MAC, and stronger digests are
  always preferred when the provider offers them (auto-detection picks
  GitHub SHA-256 over SHA-1 whenever both headers are present). MD5 is not
  supported.
- Error messages, logs and CLI output never contain secret material.
- Replay caches are only populated by *verified* messages.

Report vulnerabilities privately — see SECURITY.md. Please do not open
public issues for security reports.

## Roadmap

- Django middleware, Flask decorator.
- Optional payload-size-aware streaming verification for very large bodies.
- Async replay-cache adapters for the shared backends.

## Limitations

- `MemoryReplayCache` is process-local; use `RedisReplayCache` (any host) or
  `SQLiteReplayCache` (single host) for multi-worker deployments.
- Twilio verification needs the original request URL, so it goes through
  `verify_twilio` rather than the body-only `verify()` pipeline.
- `SQLiteReplayCache` shares state per database file; multi-host clusters
  should use `RedisReplayCache`.

## Contributing

See CONTRIBUTING.md and CONTRIBUTORS.md. `@odyntiq` is the project owner;
`@muhammadanasmahmood` is the maintainer / core contributor.

## License

MIT — see LICENSE.

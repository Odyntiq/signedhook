# signedhook

**Verify signed webhooks from any provider with one call.**

`signedhook` is a zero-dependency Python library that verifies webhook
signature headers for the schemes used by Standard Webhooks / Svix, Stripe,
GitHub (SHA-256 and legacy SHA-1), Slack, Shopify, Razorpay and Twilio —
plus a configurable generic scheme (any HMAC digest, second- or
millisecond-based timestamps) for everyone else. Auto-detection, secret
rotation, timestamp tolerance windows, pluggable replay protection (sync
and async; in-memory, Redis and SQLite backends), incremental streaming
verification for very large bodies, a retry scheduler for senders and
optional FastAPI / Django / Flask integrations are built in. The core has
no third-party dependencies and is fully typed (`py.typed`, mypy
`--strict` clean).

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
  plus sync and async `ReplayCache` protocols for message-id dedupe, with
  thread-safe in-memory, Redis and SQLite backends bundled.
- **Streaming verification** — `StreamingVerifier` checks very large bodies
  chunk by chunk with the size limit enforced mid-stream, and the framework
  integrations feed chunks straight from the ASGI/WSGI request streams
  (`stream=True`).
- **Framework integrations** — optional FastAPI dependency, Django
  middleware (+ ASGI wrapper for wire-level streaming) and Flask decorator
  with identical structured error mapping.
- **Sender-side signing** — `sign()` produces Standard Webhooks headers for
  round-trip testing and your own emitters.
- **Retry scheduler** — `RetryPolicy` gives jittered exponential backoff for
  outbound deliveries.
- **Precise, safe errors** — stable machine-readable `code` attributes;
  messages never contain secrets, signatures or payload contents.
- **Optional FastAPI integration** — a dependency factory that turns
  verification failures into structured HTTP errors (400/401/409/413).
- **CLI** — `signedhook providers | sign | verify` for debugging and CI.
- **Quality gates** — pytest (378 tests), ruff, mypy `--strict`, pip-audit,
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
Every body-signing scheme in the table also supports streaming verification;
Twilio does not (it signs the request URL and form parameters, not the body).

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
`_encoding` (decode/compare helpers), `replay` (cache protocols),
`replay_backends` (Redis / SQLite shared caches, sync and async),
`streaming` (incremental verification), `twilio` (URL + params scheme),
`retry` (sender backoff), `signing` (sender side), `fastapi` / `django` /
`flask` (optional integrations), `_http` (shared status mapping), `cli`
(shell interface), `_settings` (limits, env support).

## Installation

```bash
pip install signedhook

# optional integrations and backends
pip install "signedhook[fastapi]"    # FastAPI dependency factory
pip install "signedhook[django]"     # Django middleware
pip install "signedhook[flask]"      # Flask view decorator
pip install "signedhook[redis]"      # Redis replay caches (sync + async)
pip install "signedhook[aiosqlite]"  # async SQLite replay cache
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

### Streaming very large bodies

Every body-signing scheme signs `prefix + payload + suffix` where the
wrapper bytes come from headers, so verification can run *while the body
is still arriving* — the payload never has to be buffered whole, and the
size limit aborts oversized deliveries mid-stream:

```python
from signedhook import StreamingVerifier

verifier = StreamingVerifier(headers, secrets=SECRET, provider="stripe")
async for chunk in request.stream():
    verifier.feed(chunk)  # raises PayloadTooLargeError past the limit
result = verifier.finish()  # same VerificationResult as verify()
```

Headers are parsed, the tolerance window checked and the HMAC states
primed at construction — so unauthenticated requests fail before a single
body byte is read. `verify_stream(chunks_or_body, headers, ...)` wraps the
same flow for callers with an iterable (or a complete body).

The framework integrations run this exact pipeline for you: pass
`stream=True` to the FastAPI dependency or Flask decorator, or set
`"stream": True` on a Django route (see below). Schemes that cannot stream
(Twilio) transparently fall back to a size-capped buffered read, so the
mid-stream size guard still applies.

### FastAPI receiver

```python
from fastapi import Depends, FastAPI
from signedhook import MemoryReplayCache, webhook_dependency

app = FastAPI()
verify_hook = webhook_dependency(
    provider="standard",
    secrets=WHSEC,
    replay_cache=MemoryReplayCache(),
    stream=True,  # verify chunk by chunk off the ASGI receive channel
)


@app.post("/webhooks/svix")
async def svix_events(result=Depends(verify_hook)) -> dict:
    return {"verified_provider": result.provider}
```

Failures become structured HTTP errors:
`{"detail": {"code": "signature_mismatch", "message": ...}}` with status
400 (malformed), 401 (unauthenticated), 409 (replayed), 413 (too large).

A runnable example lives in [`examples/fastapi_receiver.py`](examples/fastapi_receiver.py).

`replay_cache=` also accepts an async cache (`AsyncReplayCache`); it is
detected and awaited automatically. With `stream=True` the dependency
consumes `request.stream()` chunk by chunk (stale timestamps fail before
any body byte is read; oversized deliveries abort mid-stream) and
re-injects the body, so body parsing keeps working. One FastAPI nuance:
when the path operation declares **body parameters**, FastAPI buffers the
body before dependencies run, so streaming degrades to chunked
verification of the already-buffered body — routes that take only
`Request`/`Depends` (like the one above) stream straight off the wire.
`offload=True` moves buffered verification to a worker thread for very
large bodies.

### Flask receiver

```python
from flask import Flask
from signedhook.flask import verify_webhook

app = Flask(__name__)


@app.post("/webhooks/stripe")
@verify_webhook(provider="stripe", secrets=STRIPE_SECRET, stream=True)
def stripe_events(result):
    return {"verified_provider": result.provider}
```

Failures return the same structured JSON (`{"detail": {"code", "message"}}`)
with the same status codes as the FastAPI integration. `stream=True`
verifies incrementally off the WSGI input stream (64 KiB chunks by
default, tunable via `chunk_size=`) and re-injects the body, so
`request.get_data()`, `request.form` and `request.get_json()` still work
in the view.

### Django middleware

```python
# settings.py
MIDDLEWARE = [
    # ... before django.middleware.csrf.CsrfViewMiddleware
    "signedhook.django.WebhookMiddleware",
]

SIGNEDHOOK_ROUTES = {
    "/webhooks/stripe/": {
        "provider": "stripe",
        "secrets": ["env:STRIPE_WEBHOOK_SECRET"],
    },
    "/webhooks/github/": {
        "provider": "github",
        "secrets": "env:GITHUB_WEBHOOK_SECRET",
        "replay": True,
        "key_header": "x-github-delivery",
    },
    "/webhooks/large/": {
        "provider": "standard",
        "secrets": "env:BIG_WEBHOOK_SECRET",
        "stream": True,  # verify chunk by chunk, not via request.body
        "chunk_size": 65536,  # read granularity (default 64 KiB)
    },
}
```

Matching requests are verified before the view runs; the result is
attached as `request.signedhook_result` and the CSRF check is skipped for
verified deliveries (webhooks carry no CSRF token). `env:NAME` secrets
resolve at startup and fail fast; non-matching paths pass through with a
dict lookup. Per-route options: `provider`, `secrets`, `tolerance`,
`max_payload_bytes`, `replay` / `replay_cache` (instance or factory),
`key_header`, `ttl_seconds`, `stream`, `chunk_size`.

With `"stream": True` the body is read chunk by chunk and fed into a
`StreamingVerifier`: stale timestamps are rejected before any body byte is
read, the size limit aborts mid-stream, and the body is restored so the
view still sees `request.body` / `request.POST`. On WSGI deployments this
streams straight off the socket-backed input; Django's own ASGI handler
buffers the body before middleware runs, so on ASGI use the wrapper below
for wire-level streaming.

#### Django + ASGI: wire-level streaming

Django cannot hand middleware an unbuffered ASGI body, so
`SignedhookASGIMiddleware` wraps the ASGI application itself and verifies
matching routes as chunks arrive on the `receive()` channel:

```python
# asgi.py
import django
from django.core.asgi import get_asgi_application

from signedhook.django import SignedhookASGIMiddleware

django.setup(set_prefix=False)
application = SignedhookASGIMiddleware(get_asgi_application())
```

Keep `WebhookMiddleware` installed as well: the wrapper stashes the result
in `request.scope["signedhook"]` and the middleware picks it up (attaches
`request.signedhook_result`, skips CSRF), so views and the rest of the
middleware stack work unchanged. Async replay caches are awaited. A
runnable example lives in
[`examples/django_asgi_receiver.py`](examples/django_asgi_receiver.py).

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

Choosing a backend:

| Backend | Scope | Best for |
|---|---|---|
| `MemoryReplayCache(maxsize=None)` | one process | dev, single-worker apps; `maxsize=` bounds memory |
| `SQLiteReplayCache(path)` | one host, all workers | gunicorn/uvicorn on one machine, zero infrastructure |
| `RedisReplayCache(client)` | one Redis, many hosts | multi-host deployments, automatic TTL eviction |

`MemoryReplayCache` is process-local by nature — workers cannot see each
other's entries — which is why the shared backends ship in the box, sync
and async:

```python
from signedhook import (
    RedisReplayCache,
    SQLiteReplayCache,
    verify_with_replay,
    AsyncRedisReplayCache,
    AsyncSQLiteReplayCache,
    verify_with_replay_async,
)
from redis import asyncio as aioredis

# sync: any Redis-compatible client (redis-py, Valkey, KeyDB)
cache = RedisReplayCache(redis_client, namespace="myapp:replay")
result = verify_with_replay(payload, headers, cache, secrets=WHSEC)

# stdlib-only, single host: pass the same path in every worker
cache = SQLiteReplayCache("/var/lib/myapp/replay.sqlite3")

# asyncio: async twins of both backends
cache = AsyncRedisReplayCache(aioredis.Redis(host="redis.internal"))
cache = await AsyncSQLiteReplayCache.connect("/var/lib/myapp/replay.sqlite3")
result = await verify_with_replay_async(payload, headers, cache, secrets=WHSEC)
```

The Redis backends run each operation as a single atomic Redis command, so
racing workers stay consistent; the SQLite backends use WAL mode with a
busy timeout and need no server — ideal for gunicorn/uvicorn workers on
one machine. The async entry points keep signature verification
synchronous and only await the two cache operations, so the event loop is
never blocked; pass `offload=True` to run the verification itself in a
worker thread (`asyncio.to_thread`) when bodies are large enough that the
inline HMAC would block for tens of milliseconds. Or implement the
two-method `ReplayCache` / `AsyncReplayCache` protocols against your own
database.

## API overview

| Call | Purpose |
|---|---|
| `verify(payload, headers, *, secrets, provider="auto", tolerance=UNSET, now=None, settings=None)` | Verify a webhook; raises typed errors |
| `verify_with_replay(..., cache, key=None, key_header=None, ttl_seconds=900)` | Verify + dedupe |
| `verify_with_replay_async(..., cache, ...)` | Async-cache variant of the above |
| `StreamingVerifier(headers, *, secrets, ...)` / `.feed(chunk)` / `.finish()` | Incremental verification for large bodies |
| `verify_stream(chunks_or_body, headers, *, secrets, ...)` | One-shot streaming convenience |
| `verify_twilio(url, params, headers, *, secrets, replay_cache=None, key=None, ttl_seconds=900)` | Verify Twilio (URL + params scheme) |
| `verify_twilio_async(...)` | Async-cache variant of the above |
| `sign(payload, *, secret, webhook_id, now=None, scheme="standard")` | Produce sender headers |
| `sign_twilio(url, params, *, secret)` | Produce Twilio signature headers |
| `RetryPolicy(...).delays()` | Jittered backoff schedule |
| `list_providers()` / `get_provider(name)` / `register_provider(provider)` | Registry |
| `GenericHMAC(name, sig_header, sig_prefix, encoding, secret_prefix, base64_secrets, ts_header, signed_template, message_key_header, digest, ts_unit)` | Custom schemes (any digest, seconds/milliseconds) |
| `MemoryReplayCache` / `RedisReplayCache` / `SQLiteReplayCache` | Sync replay caches (process-local / Redis / SQLite) |
| `AsyncMemoryReplayCache` / `AsyncRedisReplayCache` / `AsyncSQLiteReplayCache` | Async replay caches |
| `webhook_dependency(...)` (`signedhook.fastapi`) | FastAPI dependency factory (`stream=True`, `offload=True`) |
| `verify_webhook(...)` (`signedhook.flask`) | Flask view decorator (`stream=True`, `chunk_size=`) |
| `WebhookMiddleware` (`signedhook.django`) | Django middleware (`"stream": True` routes) |
| `SignedhookASGIMiddleware` (`signedhook.django`) | ASGI wrapper: wire-level streaming for Django + ASGI |

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
pytest              # 378 tests
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

- More built-in provider schemes (GitLab, Square, Discourse-style
  raw-secret HMAC) as demand warrants.

## Limitations

- `MemoryReplayCache` is process-local by design; the bundled SQLite and
  Redis backends (sync and async, see the selection table above) cover
  multi-worker and multi-host deployments.
- Twilio cannot be incrementally HMAC-verified by any receiver: the scheme
  signs the request URL plus sorted form parameters, which requires the
  complete body before the signed string can be built. Streaming framework
  integrations still enforce the payload-size limit mid-stream for Twilio
  routes via a capped buffered read, then report the scheme error.
- On Django + ASGI, Django itself buffers the request body before any
  Django middleware runs — `WebhookMiddleware(stream=True)` cannot see an
  unbuffered body there. Wrap the ASGI application with
  `SignedhookASGIMiddleware` for wire-level streaming; that is exactly
  what it exists for.
- FastAPI path operations that declare body parameters cause FastAPI to
  buffer the body before dependencies run; `stream=True` there verifies
  the cached body chunk by chunk (same semantics, no wire-level abort).
  Routes without body parameters stream straight off the ASGI channel.
- The async entry points await the two replay-cache operations; the HMAC
  itself is CPU-bound and runs inline by default (microseconds for typical
  webhook sizes). Pass `offload=True` to move it to a worker thread when
  accepting very large bodies.

## Contributing

See CONTRIBUTING.md and CONTRIBUTORS.md. `@odyntiq` is the project owner;
`@muhammadanasmahmood` is the maintainer / core contributor.

## License

MIT — see LICENSE.

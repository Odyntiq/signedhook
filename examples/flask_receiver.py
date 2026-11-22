"""Runnable Flask receiver using signedhook.

Start with:
    pip install "signedhook[flask]"
    flask --app examples.flask_receiver run --port 8000

Then post a Standard Webhooks-style request:
    curl -X POST http://localhost:5000/webhooks/svix \
      -H "webhook-id: msg_test_1" \
      -H "webhook-timestamp: $(date +%s)" \
      -H "webhook-signature: v1,..." \
      --data '{"hello":"world"}'

The VERIHOOK_WEBHOOK_SECRET environment variable configures the signing
secret (whsec_-prefixed base64 or raw). ``stream=True`` verifies the body
incrementally off the WSGI input stream (stale timestamps fail before a
single body byte is read; oversized bodies abort mid-stream) and still
re-injects the body, so the view can read it. Replace the in-memory replay
cache with a shared implementation for multi-worker deployments.
"""

from __future__ import annotations

import os

from flask import Flask

from signedhook import MemoryReplayCache
from signedhook.flask import verify_webhook

SECRET = os.environ.get("VERIHOOK_WEBHOOK_SECRET", "whsec_test_secret")
CACHE = MemoryReplayCache()

app = Flask(__name__)


@app.post("/webhooks/svix")
@verify_webhook(
    provider="standard",
    secrets=SECRET,
    replay_cache=CACHE,
    key_header="webhook-id",
    stream=True,  # verify chunk by chunk off the WSGI input stream
)
def svix_events(result):  # noqa: ANN001 - Flask view injected by the decorator
    """Receive verified Standard Webhooks / Svix deliveries."""
    return {
        "verified_provider": result.provider,
        "message_key": result.message_key,
        "payload_size": result.payload_size,
    }


if __name__ == "__main__":
    app.run(port=8000)

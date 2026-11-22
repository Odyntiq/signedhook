"""Runnable FastAPI receiver using signedhook.

Start with:
    pip install signedhook[fastapi]
    uvicorn examples.fastapi_receiver:app --port 8000

Then post a Standard Webhooks-style request:
    curl -X POST http://localhost:8000/webhooks/svix \
      -H "webhook-id: msg_test_1" \
      -H "webhook-timestamp: $(date +%s)" \
      -H "webhook-signature: v1,..." \
      --data '{"hello":"world"}'

The VERIHOOK_WEBHOOK_SECRET environment variable configures the signing
secret (whsec_-prefixed base64 or raw). Replace the in-memory replay cache
with a shared implementation for multi-worker deployments.
"""

from __future__ import annotations

import os

from fastapi import Depends, FastAPI

from signedhook import MemoryReplayCache, VerificationResult
from signedhook.fastapi import webhook_dependency

app = FastAPI(title="signedhook receiver example")

_secret = os.environ.get(
    "VERIHOOK_WEBHOOK_SECRET", "whsec_" + "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
)

verify_hook = webhook_dependency(
    provider="standard",
    secrets=_secret,
    replay_cache=MemoryReplayCache(),
    ttl_seconds=900,
)


@app.post("/webhooks/svix")
async def svix_events(result: VerificationResult = Depends(verify_hook)) -> dict[str, object]:
    """Handle a verified webhook delivery."""
    return {
        "verified": True,
        "provider": result.provider,
        "message_key": result.message_key,
        "timestamp": result.timestamp,
        "payload_size": result.payload_size,
    }

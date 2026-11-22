"""Runnable streaming receiver: verifies huge bodies chunk by chunk.

Start with:
    pip install "signedhook[fastapi]"
    uvicorn examples.streaming_receiver:app --port 8000

Unlike examples/fastapi_receiver.py this endpoint never buffers the whole
request body: each chunk read from the ASGI stream is fed straight into the
StreamingVerifier, so a body larger than VERIHOOK_MAX_PAYLOAD_BYTES is
aborted mid-upload — before the whole thing is read, and before the HMAC
work for the remaining chunks is done.

    curl -X POST http://localhost:8000/webhooks/large \
      -H "x-hub-signature-256: sha256=..." \
      --data-binary @huge-payload.json
"""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from signedhook import Settings, StreamingVerifier

SECRET = os.environ.get("VERIHOOK_WEBHOOK_SECRET", "test_secret")
MAX_BYTES = int(os.environ.get("VERIHOOK_MAX_PAYLOAD_BYTES", str(2 * 1024 * 1024)))
LIMITS = Settings(max_payload_bytes=MAX_BYTES)

app = FastAPI()


@app.post("/webhooks/large")
async def large_github_events(request: Request) -> JSONResponse:
    """Stream a (possibly huge) GitHub delivery through verification."""
    verifier = StreamingVerifier(
        request.headers,
        secrets=SECRET,
        provider="github",
        settings=LIMITS,
    )
    async for chunk in request.stream():
        verifier.feed(chunk)
    result = verifier.finish()

    return JSONResponse(
        {
            "verified_provider": result.provider,
            "payload_size": result.payload_size,
            "matched_secret_index": result.matched_secret_index,
        }
    )

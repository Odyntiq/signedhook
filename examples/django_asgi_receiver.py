"""Runnable Django receiver with wire-level streaming verification.

Django's ASGI handler buffers the whole request body before any Django
middleware runs, so SignedhookASGIMiddleware wraps the ASGI application
itself and verifies matching routes chunk by chunk as the body arrives:
stale timestamps are rejected before a single byte is read and oversized
deliveries abort mid-stream. Verified deliveries continue into Django with
the result stashed in ``request.scope["signedhook"]``; WebhookMiddleware
picks it up, attaches ``request.signedhook_result`` and skips CSRF.

Start with:
    pip install "signedhook[django]"
    python examples/django_asgi_receiver.py   # serves on :8000 via uvicorn

Then post a Standard Webhooks-style request:
    curl -X POST http://localhost:8000/webhooks/svix \
      -H "webhook-id: msg_test_1" \
      -H "webhook-timestamp: $(date +%s)" \
      -H "webhook-signature: v1,..." \
      --data '{"hello":"world"}'

The VERIHOOK_WEBHOOK_SECRET environment variable configures the signing
secret (whsec_-prefixed base64 or raw). This example uses the ASGI
middleware's in-process replay cache; point ``replay_cache`` at a shared
backend (Redis/SQLite) for multi-worker deployments.
"""

from __future__ import annotations

import os

import django
from django.conf import settings
from django.http import HttpResponse

SECRET = os.environ.get(
    "VERIHOOK_WEBHOOK_SECRET", "whsec_" + "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
)

settings.configure(
    DEBUG=True,
    ALLOWED_HOSTS=["*"],
    ROOT_URLCONF=__name__,
    SIGNEDHOOK_ROUTES={
        "/webhooks/svix/": {
            "provider": "standard",
            "secrets": SECRET,
            "key_header": "webhook-id",
            "replay": True,
            "max_payload_bytes": 64 * 1024 * 1024,
        },
    },
)

django.setup(set_prefix=False)

from django.urls import path  # noqa: E402

from signedhook.django import SignedhookASGIMiddleware  # noqa: E402


def svix_events(request):  # noqa: ANN001 - plain Django view
    """Handle a delivery the ASGI middleware already verified on the wire."""
    result = request.signedhook_result
    return HttpResponse(
        f"verified provider={result.provider} message_key={result.message_key} "
        f"payload_size={result.payload_size}\n",
        content_type="text/plain",
    )


urlpatterns = [path("webhooks/svix/", svix_events)]

# The Django middleware stack: WebhookMiddleware picks up the result the ASGI
# wrapper stashed in the scope (attach + CSRF exemption for verified routes).
_settings_middleware = settings.MIDDLEWARE
settings.MIDDLEWARE = ["signedhook.django.WebhookMiddleware", *_settings_middleware]

from django.core.asgi import get_asgi_application  # noqa: E402

# The ASGI wrapper does the streaming verification; the Django app runs inside.
asgi_application = get_asgi_application()
application = SignedhookASGIMiddleware(asgi_application)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("examples.django_asgi_receiver:application", port=8000, log_level="info")

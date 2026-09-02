"""A complete FastAPI endpoint for signed LASSO webhooks.

    pip install fastapi uvicorn
    LASSO_WEBHOOK_SECRET=whsec_... uvicorn server_fastapi:app --port 8000

Then, from another shell:

    python sign.py --url http://localhost:8000/webhooks/lasso --secret whsec_...
    python sign.py --url http://localhost:8000/webhooks/lasso --secret whsec_... --tamper

The cryptography is in ``verify.py``. What this file is actually about is taking
a bare ``Request`` so that ``await request.body()`` gives you the bytes that
arrived, rather than declaring a Pydantic model and letting FastAPI parse them
away.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from verify import WebhookVerificationError, verify

app = FastAPI()
logger = logging.getLogger("uvicorn.error")

#: Every secret this endpoint will accept, newest first. See ``server_flask.py``
#: for why this is a list.
SECRETS: list[str] = [
    stripped
    for value in os.environ.get("LASSO_WEBHOOK_SECRET", "").split(",")
    if (stripped := value.strip())
]

#: Ids already handled, so a retried delivery is not processed twice. In a real
#: service this belongs in shared storage, not in memory.
handled: set[str] = set()


@app.post("/webhooks/lasso")
async def webhook(request: Request) -> JSONResponse:
    """Verify a delivery and accept it.

    Note the signature of this function: it takes a ``Request`` and nothing
    else. Declaring a Pydantic model parameter instead is the usual FastAPI
    style, and it is what breaks webhook verification — FastAPI would parse the
    body to build the model, and the parsed object does not re-serialize back
    into the bytes the signature covers.
    """

    # The raw bytes, exactly as sent.
    raw_body: bytes = await request.body()

    try:
        payload = verify_with_any_secret(raw_body, request.headers)
    except WebhookVerificationError as error:
        # Answer 400, not 2xx. A signature that does not verify means the
        # secret, the body handling, or the request's authenticity is wrong, and
        # quietly accepting it hides all three.
        logger.warning(
            "Rejected delivery %s: %s", request.headers.get("webhook-id"), error
        )
        return JSONResponse({"error": str(error)}, status_code=400)

    # Verified. Everything from here is ordinary application code.
    message_id = request.headers["webhook-id"]

    if message_id in handled:
        # A duplicate is a success: it means we already have this one.
        logger.info("Duplicate delivery %s, already handled.", message_id)
        return JSONResponse({"status": "duplicate"}, status_code=200)

    handled.add(message_id)

    logger.info(
        "Accepted %s: %s carrying %s",
        message_id,
        payload.get("event"),
        payload.get("data"),
    )

    # Answer now and do the work afterwards. Anything slow belongs on a queue,
    # or at least in a BackgroundTask — a slow handler is treated as a failed
    # delivery and retried.
    return JSONResponse({"status": "accepted"}, status_code=202)


def verify_with_any_secret(raw_body: bytes, headers: Any) -> dict[str, Any]:
    """Verify against each configured secret in turn, returning the payload from
    whichever one accepts the delivery."""

    if not SECRETS:
        raise WebhookVerificationError("No signing secret configured.")

    last_error: WebhookVerificationError | None = None

    for secret in SECRETS:
        try:
            return verify(secret, raw_body, headers)
        except WebhookVerificationError as error:
            last_error = error

    assert last_error is not None
    raise last_error

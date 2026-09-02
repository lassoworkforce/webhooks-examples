"""A complete Flask endpoint for signed LASSO webhooks.

    pip install flask
    LASSO_WEBHOOK_SECRET=whsec_... flask --app server_flask run --port 8000

Then, from another shell:

    python sign.py --url http://localhost:8000/webhooks/lasso --secret whsec_...
    python sign.py --url http://localhost:8000/webhooks/lasso --secret whsec_... --tamper

The cryptography is in ``verify.py``. What this file is actually about is
getting the raw request body — ``request.get_data()`` — and the shape of a
handler around it. Swap ``verify`` for the library version in
``verify_with_library.py`` and nothing else here changes.
"""

from __future__ import annotations

import os
from typing import Any

from flask import Flask, jsonify, request

from verify import WebhookVerificationError, verify

app = Flask(__name__)

#: Every secret this endpoint will accept, newest first.
#:
#: A list rather than a single value so that a rotation is not an outage: keep
#: accepting the old secret until you have seen a delivery signed with the new
#: one, then drop it. Supply as a comma-separated LASSO_WEBHOOK_SECRET.
SECRETS: list[str] = [
    stripped
    for value in os.environ.get("LASSO_WEBHOOK_SECRET", "").split(",")
    if (stripped := value.strip())
]

#: Ids already handled, so a retried delivery is not processed twice.
#:
#: In a real service this belongs in shared storage — a database row keyed on
#: ``webhook-id``, or a unique constraint — since retries may land on a
#: different instance than the delivery they repeat.
handled: set[str] = set()


@app.post("/webhooks/lasso")
def webhook() -> Any:
    # The raw bytes, exactly as sent. Flask does not parse a JSON body until you
    # ask it to, so this is safe — but note that reaching for `request.json`
    # first and re-serializing it would not reproduce these bytes.
    raw_body: bytes = request.get_data()

    try:
        payload = verify_with_any_secret(raw_body, request.headers)
    except WebhookVerificationError as error:
        # Answer 400, not 2xx. A signature that does not verify means the
        # secret, the body handling, or the request's authenticity is wrong, and
        # quietly accepting it hides all three.
        app.logger.warning(
            "Rejected delivery %s: %s", request.headers.get("webhook-id"), error
        )
        return jsonify(error=str(error)), 400

    # Verified. Everything from here is ordinary application code.
    message_id = request.headers["webhook-id"]

    if message_id in handled:
        # A duplicate is a success: it means we already have this one. Answering
        # anything else invites yet another retry.
        app.logger.info("Duplicate delivery %s, already handled.", message_id)
        return jsonify(status="duplicate"), 200

    handled.add(message_id)

    app.logger.info(
        "Accepted %s: %s carrying %s",
        message_id,
        payload.get("event"),
        payload.get("data"),
    )

    # Answer now and do the work afterwards. A slow handler is treated as a
    # failed delivery and retried, so anything that might be slow — a database
    # write, an outbound call — belongs on a queue rather than in this function.
    return jsonify(status="accepted"), 202


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


if __name__ == "__main__":
    if not SECRETS:
        raise SystemExit(
            "Set LASSO_WEBHOOK_SECRET (comma-separated to accept several)."
        )

    print(f"Accepting {len(SECRETS)} signing secret(s).")
    app.run(port=int(os.environ.get("PORT", 8000)))

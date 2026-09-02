"""Send a correctly signed webhook to your own endpoint.

LASSO does the signing in production, so this exists for one reason: to let you
exercise your handler before a real delivery arrives, including the cases where
it is supposed to say no. An endpoint that has only ever been shown a valid
request has not been tested.

    # Sign a sample payload and POST it
    python sign.py --url http://localhost:8000/webhooks/lasso --secret whsec_...

    # Print a curl command instead of sending anything
    python sign.py --secret whsec_... --curl

    # Deliveries your handler must reject
    python sign.py --url ... --secret ... --stale     # signed 15 minutes ago
    python sign.py --url ... --secret ... --tamper    # body altered after signing
    python sign.py --url ... --secret ... --unsigned  # no signature headers

The secret may also come from LASSO_WEBHOOK_SECRET. It only has to match what
your handler verifies with, so use a throwaway rather than the secret LASSO
issued you — the one in `fixtures/signed-delivery.json` will do. A shell
history is no place for a production secret.

Uses only the standard library, so it runs wherever Python does.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import time
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime

from verify import sign

SAMPLE_PAYLOAD = {
    "event": "test.event",
    "id": 4815162342,
    "data": "foobär",
}

#: How stale ``--stale`` makes a delivery: past any sane tolerance.
STALE_SECONDS = 15 * 60


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Send a signed test webhook to your own endpoint.",
    )
    parser.add_argument("--url", help="POST the signed delivery here")
    parser.add_argument(
        "--curl", action="store_true", help="print a curl command instead of sending"
    )
    parser.add_argument(
        "--secret", help="signing secret (or set LASSO_WEBHOOK_SECRET)"
    )
    parser.add_argument(
        "--body-file", help="JSON body to send, instead of the built-in sample"
    )
    parser.add_argument("--id", help="webhook-id to use, instead of a generated one")
    parser.add_argument(
        "--stale",
        action="store_true",
        help="sign with a 15-minute-old timestamp (must be rejected)",
    )
    parser.add_argument(
        "--tamper",
        action="store_true",
        help="alter the body after signing (must be rejected)",
    )
    parser.add_argument(
        "--unsigned",
        action="store_true",
        help="send no signature headers at all (must be rejected)",
    )

    args = parser.parse_args()

    secret = args.secret or os.environ.get("LASSO_WEBHOOK_SECRET")

    if not secret:
        parser.error("a --secret (or LASSO_WEBHOOK_SECRET) is required")

    if not args.url and not args.curl:
        parser.error("give a --url to POST to, or --curl to print a command")

    # Serialized once, here, and never re-serialized: these exact bytes are what
    # gets signed and what gets sent. Doing it any other way is the mistake this
    # whole repository is about.
    if args.body_file:
        with open(args.body_file, encoding="utf-8") as handle:
            body = handle.read()
    else:
        body = json.dumps(SAMPLE_PAYLOAD, ensure_ascii=False, separators=(",", ":"))

    message_id = args.id or f"{datetime.now(UTC):%Y/%m/%d}/{uuid.uuid4().hex[:8]}.json"
    timestamp = int(time.time()) - (STALE_SECONDS if args.stale else 0)

    headers = {"content-type": "application/json"}

    if not args.unsigned:
        headers |= sign(secret, message_id, timestamp, body)

    # Signed above, altered here. The signature stays valid for the original
    # bytes, which is exactly the forgery a verifying endpoint has to catch.
    sent = tamper(body) if args.tamper else body

    if args.curl:
        print(curl(args.url or "https://example.invalid/webhooks/lasso", headers, sent))
        return 0

    status, reason, text = post(args.url, headers, sent)

    print(f"POST {args.url}")
    for name, value in headers.items():
        print(f"  {name}: {value}")
    print(f"\nbody: {sent}")
    print(f"\n→ {status} {reason}")
    if text:
        print(text)

    # A rejection is the expected outcome for the deliberately-bad modes, so
    # report on whether the endpoint did the right thing rather than on the
    # status alone.
    should_reject = args.stale or args.tamper or args.unsigned
    rejected = not 200 <= status < 300

    if should_reject:
        if rejected:
            print("\n✓ Correctly rejected.")
            return 0
        print("\n✗ This delivery should NOT have been accepted. Check your verification.")
        return 1

    if rejected:
        print("\n✗ A valid delivery was rejected.")
        return 1

    print("\n✓ Accepted.")
    return 0


def post(url: str, headers: dict[str, str], body: str) -> tuple[int, str, str]:
    """POST the delivery and return the status, reason, and response body.

    A ``4xx`` is an expected outcome here rather than an error, so the
    ``HTTPError`` that ``urlopen`` raises for one is unwrapped into a result.
    """

    request = urllib.request.Request(
        url, data=body.encode("utf-8"), headers=headers, method="POST"
    )

    try:
        with urllib.request.urlopen(request) as response:
            return response.status, response.reason, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        return error.code, error.reason, error.read().decode("utf-8")


def tamper(original: str) -> str:
    """Change the body without re-signing it."""

    return json.dumps(
        json.loads(original) | {"data": "tampered"}, ensure_ascii=False, separators=(",", ":")
    )


def curl(url: str, headers: dict[str, str], body: str) -> str:
    flags = [f"  -H {shlex.quote(f'{name}: {value}')}" for name, value in headers.items()]

    return " \\\n".join(
        [
            f"curl -sS -X POST {shlex.quote(url)}",
            *flags,
            f"  --data-binary {shlex.quote(body)}",
        ]
    )


if __name__ == "__main__":
    raise SystemExit(main())

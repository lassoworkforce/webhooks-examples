"""Verifying a LASSO webhook signature with nothing but the standard library.

This is the whole of what the ``standardwebhooks`` package does for the
verification path, written against ``hmac`` and ``hashlib`` so you can read it,
copy it, and satisfy yourself that nothing surprising is happening. If you would
rather not maintain it, use the library instead — see
``verify_with_library.py``. The two agree; ``test_verify.py`` checks that they
do.

The signature covers ``{webhook-id}.{webhook-timestamp}.{raw body}``, keyed by
the base64-decoded secret. Everything below is bookkeeping around that one line.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import time
from collections.abc import Mapping
from typing import Any

__all__ = [
    "DEFAULT_TOLERANCE_SECONDS",
    "WebhookVerificationError",
    "sign",
    "verify",
]


class WebhookVerificationError(Exception):
    """Raised for every reason a delivery may be rejected."""


SECRET_PREFIX = "whsec_"
SIGNATURE_VERSION = "v1"

#: HMAC-SHA256 is 32 bytes. A candidate of any other length cannot match.
DIGEST_BYTES = 32

#: How far ``webhook-timestamp`` may sit from your own clock. Five minutes
#: either side is what the Standard Webhooks libraries allow: long enough to
#: absorb ordinary clock drift, short enough that a captured request stops being
#: replayable quickly.
DEFAULT_TOLERANCE_SECONDS = 5 * 60


def verify(
    secret: str,
    body: str | bytes,
    headers: Mapping[str, str],
    *,
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
    now: float | None = None,
) -> Any:
    """Verify a delivery and return its parsed payload.

    ``body`` must be the **raw** request body, exactly as received — ``bytes``,
    or a string that has not been through a JSON round trip. If your framework
    already parsed it, the bytes the signature covers are gone; see this
    directory's README for how to keep them.

    ``now`` is an injectable clock, present so that tests need not depend on the
    current time.

    Raises `WebhookVerificationError` on a bad signature, a missing header, a
    stale timestamp, or an unusable secret. It never returns ``False``: there is
    no path where a caller can forget to check a result.
    """

    message_id = _required_header(headers, "webhook-id")
    timestamp = _required_header(headers, "webhook-timestamp")
    signature = _required_header(headers, "webhook-signature")

    _verify_timestamp(timestamp, tolerance_seconds, now)

    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    expected = _digest(_secret_key(secret), message_id, timestamp, body_bytes)

    if not _matches(signature, expected):
        raise WebhookVerificationError("No matching signature found.")

    # Parse only now. Doing it earlier would mean acting on the payload — even
    # just to reach a field — before knowing it came from LASSO.
    return json.loads(body_bytes)


def sign(secret: str, message_id: str, timestamp: int, body: str | bytes) -> dict[str, str]:
    """Produce the three headers that authenticate ``body``.

    Sending is LASSO's job, so you need this only to sign test deliveries to
    your own endpoint — which ``sign.py`` does, and which is the one honest way
    to confirm your handler rejects what it should.
    """

    body_bytes = body.encode("utf-8") if isinstance(body, str) else body
    digest = _digest(_secret_key(secret), message_id, str(timestamp), body_bytes)

    return {
        "webhook-id": message_id,
        "webhook-timestamp": str(timestamp),
        "webhook-signature": f"{SIGNATURE_VERSION},{base64.b64encode(digest).decode()}",
    }


def _digest(key: bytes, message_id: str, timestamp: str, body: bytes) -> bytes:
    """The signature over ``{id}.{timestamp}.{body}``, as raw bytes."""

    # Concatenated as bytes rather than built as a string: the body may contain
    # any UTF-8, and going through a string risks a re-encoding that changes it.
    signed_content = f"{message_id}.{timestamp}.".encode() + body

    return hmac.new(key, signed_content, hashlib.sha256).digest()


def _secret_key(secret: str) -> bytes:
    """The HMAC key: the secret with its prefix removed and base64 decoded.

    Decoded with ``validate=True``, because the base64 decoders otherwise
    silently discard anything outside their alphabet. A mistyped or free-form
    secret would then decode to arbitrary bytes and produce a signature that
    simply never matches — a failure with no error attached to it, and a
    genuinely unpleasant afternoon. Failing here says what is actually wrong.
    """

    encoded = secret.removeprefix(SECRET_PREFIX)

    try:
        # Restore padding the issuer may have trimmed, as the reference
        # libraries do. Padded to the next multiple of four rather than always
        # appending "==", which those libraries can afford only because they do
        # not validate.
        key = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise WebhookVerificationError(
            "Signing secret is not valid base64. Use it exactly as issued."
        ) from None

    if not key:
        raise WebhookVerificationError("Signing secret is empty.")

    return key


def _matches(header: str, expected: bytes) -> bool:
    """Whether any signature in the header matches.

    The header may carry several, space-separated, each tagged with its scheme
    version. Accepting a match from any of them is what lets LASSO rotate a
    secret, or introduce a ``v2`` alongside ``v1``, without your endpoint
    dropping deliveries in between. Versions you do not recognise are skipped
    rather than treated as failures.
    """

    found = False

    for candidate in header.split(" "):
        version, _, encoded = candidate.partition(",")

        if version != SIGNATURE_VERSION or not encoded:
            continue

        try:
            supplied = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError):
            continue

        if len(supplied) != DIGEST_BYTES:
            continue

        # Constant time. A plain ``==`` would leak, through how long it takes to
        # fail, how much of a guessed signature was correct.
        if hmac.compare_digest(supplied, expected):
            found = True

    return found


def _verify_timestamp(timestamp: str, tolerance_seconds: int, now: float | None) -> None:
    """Reject a delivery signed too long ago, or too far in the future."""

    current = int(time.time() if now is None else now)

    try:
        signed = int(timestamp)
    except ValueError:
        raise WebhookVerificationError(
            f"Invalid webhook-timestamp: {timestamp}"
        ) from None

    if signed < current - tolerance_seconds:
        raise WebhookVerificationError("Message timestamp too old.")

    # Checked in both directions: LASSO's clock may be a little ahead of yours,
    # and a timestamp far in the future is a sign of something wrong either way.
    if signed > current + tolerance_seconds:
        raise WebhookVerificationError("Message timestamp too new.")


def _required_header(headers: Mapping[str, str], name: str) -> str:
    """Look a header up case-insensitively.

    HTTP header names are case-insensitive and different servers, proxies, and
    frameworks normalise them differently. LASSO sends these three lowercase;
    this makes that irrelevant. Note that some frameworks hand you a mapping
    that is already case-insensitive, in which case this costs nothing anyway.
    """

    for key, value in headers.items():
        if key.casefold() == name and value:
            return value

    raise WebhookVerificationError(f"Missing required header: {name}")

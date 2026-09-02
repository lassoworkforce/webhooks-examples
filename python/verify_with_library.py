"""Verifying a LASSO webhook with the ``standardwebhooks`` package.

    pip install standardwebhooks

This is the path to take unless you have a reason not to add a dependency. The
library is the reference implementation of the specification LASSO signs
against, so using it means the verification is not code you own or maintain.

``verify.py`` in this directory does the same job with nothing but the standard
library, if you would rather read and copy forty lines than take a package.

Run this file directly to check the shared fixture:

    python verify_with_library.py
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from standardwebhooks.webhooks import Webhook


def verify_delivery(secret: str, raw_body: str | bytes, headers: Mapping[str, str]) -> Any:
    """Verify a delivery and return its parsed payload.

    ``raw_body`` must be the unparsed request body. This is the whole
    integration — the library handles the signature, the timestamp tolerance,
    multiple signatures in one header, and the optional ``whsec_`` prefix on the
    secret.

    Raises on a bad signature, a missing header, or a stale timestamp. Let it
    raise and answer ``400``; do not catch it into a ``2xx``.
    """

    body = raw_body.decode("utf-8") if isinstance(raw_body, bytes) else raw_body

    # `dict(request.headers)` is fine for most frameworks. The library looks the
    # three headers up itself, and tolerates the rest being present.
    return Webhook(secret).verify(body, dict(headers))


def _main() -> int:
    """Check that the library reproduces the fixture's signature.

    The fixture's timestamp is fixed in the past, so a stock ``verify()`` would
    reject it as stale no matter how correct the signature is. Signature
    correctness is what this checks, so it is compared directly. Your own
    endpoint should keep the freshness check — see the repository README on
    testing the two separately.
    """

    import json
    from datetime import UTC, datetime
    from pathlib import Path

    fixture = json.loads(
        (Path(__file__).parent.parent / "fixtures" / "signed-delivery.json").read_text()
    )

    computed = Webhook(fixture["secret"]).sign(
        fixture["headers"]["webhook-id"],
        datetime.fromtimestamp(int(fixture["headers"]["webhook-timestamp"]), UTC),
        fixture["body"],
    )
    expected = fixture["headers"]["webhook-signature"]

    print(f"expected: {expected}")
    print(f"computed: {computed}")
    print("\n✓ signature matches" if computed == expected else "\n✗ MISMATCH")

    return 0 if computed == expected else 1


if __name__ == "__main__":
    raise SystemExit(_main())

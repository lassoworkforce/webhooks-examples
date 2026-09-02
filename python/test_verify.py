"""Tests for the standard-library verifier.

    pytest

Two of these matter more than the rest. The fixture test pins our signature
computation to a vector the Standard Webhooks reference implementation produced,
so a passing run means we agree with the specification rather than merely with
ourselves. The interop tests check that the library accepts what ``sign``
produces and produces what ``verify`` accepts, in both directions.

The rest are the failure cases. They are the point of the file: any verifier
accepts a valid delivery, and the useful question is whether it rejects
everything else. If you copy ``verify.py``, copy these too.
"""

from __future__ import annotations

import base64
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from standardwebhooks.webhooks import Webhook

from verify import DEFAULT_TOLERANCE_SECONDS, WebhookVerificationError, sign, verify

FIXTURE: dict[str, Any] = json.loads(
    (Path(__file__).parent.parent / "fixtures" / "signed-delivery.json").read_text(
        encoding="utf-8"
    )
)

SECRET: str = FIXTURE["secret"]
BODY: str = FIXTURE["body"]
HEADERS: dict[str, str] = FIXTURE["headers"]
TIMESTAMP = int(HEADERS["webhook-timestamp"])


@pytest.fixture
def fresh():
    """Sign a delivery now, for the cases that should not depend on a clock."""

    def _fresh(
        secret: str = SECRET,
        body: str = BODY,
        message_id: str = "2026/09/02/aaaaaaaa.json",
    ) -> tuple[str, str, dict[str, str]]:
        return secret, body, sign(secret, message_id, int(time.time()), body)

    return _fresh


class TestTheSharedFixture:
    def test_verifies_and_returns_the_parsed_payload(self) -> None:
        payload = verify(SECRET, BODY, HEADERS, now=TIMESTAMP)

        # Non-ASCII on purpose: the signature covers UTF-8 bytes, and a verifier
        # that measures or re-encodes the body as characters fails right here.
        assert payload["event"] == "test.event"
        assert payload["data"] == "foobär"

    def test_verifies_identically_from_bytes(self) -> None:
        assert verify(SECRET, BODY.encode("utf-8"), HEADERS, now=TIMESTAMP)

    def test_is_rejected_as_stale_against_the_real_clock(self) -> None:
        # The fixture is deliberately fixed in the past. Signature correctness
        # and freshness are separate checks, and this proves the second one runs.
        with pytest.raises(WebhookVerificationError, match="too old"):
            verify(SECRET, BODY, HEADERS)


class TestAgreementWithTheReferenceImplementation:
    def test_we_compute_the_signature_the_library_computes(self) -> None:
        library = Webhook(SECRET).sign(
            HEADERS["webhook-id"], datetime.fromtimestamp(TIMESTAMP, UTC), BODY
        )

        assert library == HEADERS["webhook-signature"]
        assert (
            sign(SECRET, HEADERS["webhook-id"], TIMESTAMP, BODY)["webhook-signature"]
            == library
        )

    def test_the_library_accepts_what_we_sign(self, fresh) -> None:
        secret, body, headers = fresh()

        assert Webhook(secret).verify(body, headers)

    def test_we_accept_what_the_library_signs(self) -> None:
        timestamp = int(time.time())
        message_id = "2026/09/02/bbbbbbbb.json"
        signature = Webhook(SECRET).sign(
            message_id, datetime.fromtimestamp(timestamp, UTC), BODY
        )

        assert verify(
            SECRET,
            BODY,
            {
                "webhook-id": message_id,
                "webhook-timestamp": str(timestamp),
                "webhook-signature": signature,
            },
        )


class TestRejects:
    def test_a_tampered_body(self, fresh) -> None:
        secret, body, headers = fresh()

        with pytest.raises(WebhookVerificationError):
            verify(secret, body.replace("foobär", "tampered"), headers)

    def test_a_body_that_has_been_through_a_json_round_trip(self, fresh) -> None:
        # The mistake this repository exists to prevent. Python's `json.dumps`
        # defaults differ from what arrives on the wire in two ways at once —
        # it escapes non-ASCII and puts spaces after separators — so a
        # re-serialized body is not the signed body.
        secret, body, headers = fresh()
        reserialized = json.dumps(json.loads(body))

        assert reserialized != body

        with pytest.raises(WebhookVerificationError, match="No matching signature"):
            verify(secret, reserialized, headers)

        # The same delivery verifies when the bytes are left alone.
        assert verify(secret, body, headers)

    def test_a_body_reserialized_with_matching_separators(self, fresh) -> None:
        # Even matching `json.dumps` to the sender's arguments is not a fix. A
        # decimal written 7.50 comes back as 7.5, and that one delivery fails
        # while every other keeps working — an intermittent failure you cannot
        # reproduce. Verify the bytes as received.
        body = '{"value":7.50}'
        secret, _, headers = fresh(body=body)
        reserialized = json.dumps(
            json.loads(body), ensure_ascii=False, separators=(",", ":")
        )

        assert reserialized != body

        with pytest.raises(WebhookVerificationError, match="No matching signature"):
            verify(secret, reserialized, headers)

        assert verify(secret, body, headers)

    def test_the_wrong_secret(self, fresh) -> None:
        _, body, headers = fresh()
        other = "whsec_" + base64.b64encode(bytes(24)).decode()

        with pytest.raises(WebhookVerificationError, match="No matching signature"):
            verify(other, body, headers)

    def test_a_signature_for_a_different_webhook_id(self, fresh) -> None:
        # The id is inside the signed content, so it cannot be swapped after.
        secret, body, headers = fresh()

        with pytest.raises(WebhookVerificationError, match="No matching signature"):
            verify(secret, body, headers | {"webhook-id": "2026/09/02/deadbeef.json"})

    def test_a_signature_lifted_onto_a_different_timestamp(self, fresh) -> None:
        secret, body, headers = fresh()
        moved = str(int(headers["webhook-timestamp"]) - 1)

        with pytest.raises(WebhookVerificationError, match="No matching signature"):
            verify(secret, body, headers | {"webhook-timestamp": moved})

    def test_a_timestamp_too_far_in_the_future(self, fresh) -> None:
        secret, body, headers = fresh()

        with pytest.raises(WebhookVerificationError, match="too new"):
            verify(secret, body, headers, now=time.time() - 20 * 60)

    def test_a_non_numeric_timestamp(self, fresh) -> None:
        secret, body, headers = fresh()

        with pytest.raises(WebhookVerificationError, match="Invalid webhook-timestamp"):
            verify(secret, body, headers | {"webhook-timestamp": "yesterday"})

    def test_a_free_form_secret_that_is_not_base64(self, fresh) -> None:
        # Left unchecked, the base64 decoders discard characters outside their
        # alphabet, so this would decode to arbitrary bytes and produce a
        # signature that never matches, with no error to explain why.
        _, body, headers = fresh()

        with pytest.raises(WebhookVerificationError, match="not valid base64"):
            verify("hunter2-correct-horse-battery-staple", body, headers)

    def test_a_signature_of_the_right_shape_but_the_wrong_length(self, fresh) -> None:
        secret, body, headers = fresh()

        with pytest.raises(WebhookVerificationError, match="No matching signature"):
            verify(secret, body, headers | {"webhook-signature": "v1,YWJj"})

    def test_a_signature_whose_only_version_is_one_we_do_not_know(self, fresh) -> None:
        secret, body, headers = fresh()
        future = headers["webhook-signature"].replace("v1,", "v2,")

        with pytest.raises(WebhookVerificationError, match="No matching signature"):
            verify(secret, body, headers | {"webhook-signature": future})

    @pytest.mark.parametrize(
        "missing", ["webhook-id", "webhook-timestamp", "webhook-signature"]
    )
    def test_a_delivery_with_a_missing_header(self, fresh, missing: str) -> None:
        secret, body, headers = fresh()
        without = {k: v for k, v in headers.items() if k != missing}

        with pytest.raises(WebhookVerificationError, match=missing):
            verify(secret, body, without)

    def test_an_empty_header_rather_than_an_absent_one(self, fresh) -> None:
        secret, body, headers = fresh()

        with pytest.raises(WebhookVerificationError, match="Missing required header"):
            verify(secret, body, headers | {"webhook-signature": ""})


class TestAccepts:
    def test_the_secret_with_or_without_its_whsec_prefix(self, fresh) -> None:
        bare = SECRET.removeprefix("whsec_")

        # Signed with one form, verified with the other, in both directions.
        assert verify(SECRET, BODY, fresh(secret=bare)[2])
        assert verify(bare, BODY, fresh(secret=SECRET)[2])

    def test_a_secret_whose_base64_padding_has_been_trimmed(self, fresh) -> None:
        padded = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc="
        trimmed = padded.rstrip("=")

        assert verify(trimmed, BODY, fresh(secret=padded)[2])

    def test_headers_in_any_casing(self, fresh) -> None:
        secret, body, headers = fresh()
        shouted = {name.upper(): value for name, value in headers.items()}

        assert verify(secret, body, shouted)

    def test_one_valid_signature_among_several(self, fresh) -> None:
        # What makes a secret rotation survivable: the header may carry a
        # signature from every secret in play, and any match is a match.
        secret, body, headers = fresh()
        signature = headers["webhook-signature"]
        other = "v1," + base64.b64encode(bytes(32)).decode()

        for header in (
            f"{other} {signature}",
            f"{signature} {other}",
            f"v2,unknown {signature}",
        ):
            assert verify(secret, body, headers | {"webhook-signature": header})

    def test_a_delivery_at_the_outer_edge_of_the_tolerance(self, fresh) -> None:
        secret, body, headers = fresh()
        signed = int(headers["webhook-timestamp"])
        edge = signed + DEFAULT_TOLERANCE_SECONDS

        assert verify(secret, body, headers, now=edge)

        with pytest.raises(WebhookVerificationError, match="too old"):
            verify(secret, body, headers, now=edge + 1)

/**
 * Tests for the dependency-free verifier.
 *
 *     npm test
 *
 * Two of these matter more than the rest. The fixture test pins our signature
 * computation to a vector the Standard Webhooks reference implementation
 * produced, so a passing run means we agree with the specification rather than
 * merely with ourselves. The interop tests check that the library accepts what
 * `sign` produces and produces what `verify` accepts, in both directions.
 *
 * The rest are the failure cases. They are the point of the file: any verifier
 * accepts a valid delivery, and the useful question is whether it rejects
 * everything else. If you copy `verify.ts`, copy these too.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { Webhook } from "standardwebhooks";

import { verify, sign, WebhookVerificationError } from "./verify.ts";

interface Fixture {
  secret: string;
  headers: Record<string, string>;
  body: string;
}

const fixture: Fixture = JSON.parse(
  readFileSync(new URL("../fixtures/signed-delivery.json", import.meta.url), "utf8"),
);

const FIXTURE_TIMESTAMP = Number(fixture.headers["webhook-timestamp"]);

/** The fixture's own signing moment, so its fixed timestamp is not stale. */
const atSigningTime = { now: new Date(FIXTURE_TIMESTAMP * 1000) };

/** A freshly signed delivery, for the cases that should not depend on a clock. */
function fresh(overrides: { secret?: string; body?: string; id?: string } = {}) {
  const secret = overrides.secret ?? fixture.secret;
  const body = overrides.body ?? fixture.body;
  const id = overrides.id ?? "2026/09/02/aaaaaaaa.json";
  const timestamp = Math.floor(Date.now() / 1000);

  return { secret, body, headers: sign(secret, id, timestamp, body) };
}

describe("the shared fixture", () => {
  test("verifies, and returns the parsed payload", () => {
    const payload = verify<{ event: string; data: string }>(
      fixture.secret,
      fixture.body,
      fixture.headers,
      atSigningTime,
    );

    // Non-ASCII on purpose: the signature covers UTF-8 bytes, and a verifier
    // that measures or re-encodes the body as characters fails right here.
    assert.equal(payload.event, "test.event");
    assert.equal(payload.data, "foobär");
  });

  test("verifies identically from a Buffer", () => {
    assert.doesNotThrow(() =>
      verify(fixture.secret, Buffer.from(fixture.body, "utf8"), fixture.headers, atSigningTime),
    );
  });

  test("is rejected as stale against the real clock", () => {
    // The fixture is deliberately fixed in the past. Signature correctness and
    // freshness are separate checks, and this is what proves the second one runs.
    assert.throws(
      () => verify(fixture.secret, fixture.body, fixture.headers),
      /timestamp too old/i,
    );
  });
});

describe("agreement with the reference implementation", () => {
  test("we compute the signature the library computes", () => {
    const library = new Webhook(fixture.secret).sign(
      fixture.headers["webhook-id"],
      new Date(FIXTURE_TIMESTAMP * 1000),
      fixture.body,
    );

    assert.equal(library, fixture.headers["webhook-signature"]);
    assert.equal(
      sign(fixture.secret, fixture.headers["webhook-id"], FIXTURE_TIMESTAMP, fixture.body)[
        "webhook-signature"
      ],
      library,
    );
  });

  test("the library accepts what we sign", () => {
    const { secret, body, headers } = fresh();

    assert.doesNotThrow(() => new Webhook(secret).verify(body, headers));
  });

  test("we accept what the library signs", () => {
    const timestamp = Math.floor(Date.now() / 1000);
    const id = "2026/09/02/bbbbbbbb.json";
    const signature = new Webhook(fixture.secret).sign(
      id,
      new Date(timestamp * 1000),
      fixture.body,
    );

    assert.doesNotThrow(() =>
      verify(fixture.secret, fixture.body, {
        "webhook-id": id,
        "webhook-timestamp": String(timestamp),
        "webhook-signature": signature,
      }),
    );
  });
});

describe("rejects", () => {
  test("a tampered body", () => {
    const { secret, headers } = fresh();

    assert.throws(
      () => verify(secret, fixture.body.replace("foobär", "tampered"), headers),
      WebhookVerificationError,
    );
  });

  test("a body that has been through a JSON round trip", () => {
    // The mistake this repository exists to prevent.
    //
    // Note what makes it nasty. For the fixture payload, `JSON.parse` followed
    // by `JSON.stringify` happens to reproduce the received bytes exactly, so a
    // handler that re-serializes appears to work — until a payload arrives that
    // does not survive the trip. Below, an integer too large for a JavaScript
    // number and a decimal written with a trailing zero both come back
    // different, and verification fails on that delivery alone. Verifying the
    // raw bytes is not a precaution against a rare case; it is the only way to
    // avoid an intermittent failure you cannot reproduce.
    for (const body of ['{"id":10000000000000000001}', '{"value":7.50}']) {
      const { headers } = fresh({ body });
      const reserialized = JSON.stringify(JSON.parse(body));

      assert.notEqual(reserialized, body);
      assert.throws(
        () => verify(fixture.secret, reserialized, headers),
        /no matching signature/i,
      );

      // The same delivery verifies when the bytes are left alone.
      assert.doesNotThrow(() => verify(fixture.secret, body, headers));
    }
  });

  test("the wrong secret", () => {
    const { body, headers } = fresh();

    assert.throws(
      () => verify("whsec_" + Buffer.alloc(24, 7).toString("base64"), body, headers),
      /no matching signature/i,
    );
  });

  test("a signature for a different webhook-id", () => {
    // The id is inside the signed content, so it cannot be swapped afterwards.
    const { secret, body, headers } = fresh();

    assert.throws(
      () => verify(secret, body, { ...headers, "webhook-id": "2026/09/02/deadbeef.json" }),
      /no matching signature/i,
    );
  });

  test("a signature lifted onto a different timestamp", () => {
    const { secret, body, headers } = fresh();
    const moved = String(Number(headers["webhook-timestamp"]) - 1);

    assert.throws(
      () => verify(secret, body, { ...headers, "webhook-timestamp": moved }),
      /no matching signature/i,
    );
  });

  test("a timestamp too far in the future", () => {
    const { secret, body, headers } = fresh();
    const ahead = new Date(Date.now() - 20 * 60 * 1000);

    assert.throws(() => verify(secret, body, headers, { now: ahead }), /too new/i);
  });

  test("a non-numeric timestamp", () => {
    const { secret, body, headers } = fresh();

    assert.throws(
      () => verify(secret, body, { ...headers, "webhook-timestamp": "yesterday" }),
      /invalid webhook-timestamp/i,
    );
  });

  test("a free-form secret that is not base64", () => {
    // Left unchecked, the base64 decoders discard characters outside their
    // alphabet, so this would decode to arbitrary bytes and produce a signature
    // that never matches, with no error to explain why.
    const { body, headers } = fresh();

    assert.throws(
      () => verify("hunter2-correct-horse-battery-staple", body, headers),
      /not valid base64/i,
    );
  });

  test("a signature of the right shape but the wrong length", () => {
    const { secret, body, headers } = fresh();

    assert.throws(
      () => verify(secret, body, { ...headers, "webhook-signature": "v1,YWJj" }),
      /no matching signature/i,
    );
  });

  test("a signature whose only version is one we do not know", () => {
    const { secret, body, headers } = fresh();
    const future = headers["webhook-signature"].replace("v1,", "v2,");

    assert.throws(
      () => verify(secret, body, { ...headers, "webhook-signature": future }),
      /no matching signature/i,
    );
  });

  for (const missing of ["webhook-id", "webhook-timestamp", "webhook-signature"]) {
    test(`a delivery with no ${missing}`, () => {
      const { secret, body, headers } = fresh();
      const { [missing]: _, ...rest } = headers;

      assert.throws(() => verify(secret, body, rest), new RegExp(missing));
    });
  }

  test("an empty header rather than an absent one", () => {
    const { secret, body, headers } = fresh();

    assert.throws(
      () => verify(secret, body, { ...headers, "webhook-signature": "" }),
      /missing required header/i,
    );
  });
});

describe("accepts", () => {
  test("the secret with or without its whsec_ prefix", () => {
    const bare = fixture.secret.replace("whsec_", "");
    const { headers } = fresh({ secret: bare });

    // Signed with one form, verified with the other, in both directions.
    assert.doesNotThrow(() => verify(fixture.secret, fixture.body, headers));
    assert.doesNotThrow(() => verify(bare, fixture.body, fresh().headers));
  });

  test("a secret whose base64 padding has been trimmed", () => {
    const padded = "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnc=";
    const trimmed = padded.replace(/=+$/, "");
    const { headers } = fresh({ secret: padded });

    assert.doesNotThrow(() => verify(trimmed, fixture.body, headers));
  });

  test("headers in any casing", () => {
    const { secret, body, headers } = fresh();
    const shouted = Object.fromEntries(
      Object.entries(headers).map(([name, value]) => [name.toUpperCase(), value]),
    );

    assert.doesNotThrow(() => verify(secret, body, shouted));
  });

  test("a header Node has presented as an array", () => {
    const { secret, body, headers } = fresh();

    assert.doesNotThrow(() =>
      verify(secret, body, { ...headers, "webhook-id": [headers["webhook-id"]] }),
    );
  });

  test("one valid signature among several", () => {
    // What makes a secret rotation survivable: the header may carry a signature
    // from every secret in play, and any match is a match.
    const { secret, body, headers } = fresh();
    const others = "v1,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    for (const header of [
      `${others} ${headers["webhook-signature"]}`,
      `${headers["webhook-signature"]} ${others}`,
      `v2,unknown ${headers["webhook-signature"]}`,
    ]) {
      assert.doesNotThrow(() =>
        verify(secret, body, { ...headers, "webhook-signature": header }),
      );
    }
  });

  test("a delivery at the outer edge of the tolerance", () => {
    const { secret, body, headers } = fresh();
    const signed = Number(headers["webhook-timestamp"]);
    const edge = new Date((signed + 5 * 60) * 1000);

    assert.doesNotThrow(() => verify(secret, body, headers, { now: edge }));
    assert.throws(() =>
      verify(secret, body, headers, { now: new Date(edge.getTime() + 1000) }),
    );
  });
});

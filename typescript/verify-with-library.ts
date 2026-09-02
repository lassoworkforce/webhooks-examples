/**
 * Verifying a LASSO webhook with the `standardwebhooks` package.
 *
 *     npm install standardwebhooks
 *
 * This is the path to take unless you have a reason not to add a dependency.
 * The library is the reference implementation of the specification LASSO signs
 * against, so using it means the verification is not code you own or maintain.
 *
 * `verify.ts` in this directory does the same job with no dependency, if you
 * would rather read and copy forty lines than take a package.
 */

import { Webhook } from "standardwebhooks";

/**
 * Verify a delivery and return its parsed payload.
 *
 * `rawBody` must be the unparsed request body. This is the whole integration —
 * the library handles the signature, the timestamp tolerance, multiple
 * signatures in one header, and the optional `whsec_` prefix on the secret.
 *
 * Throws on a bad signature, a missing header, or a stale timestamp. Let it
 * throw and answer `400`; do not catch it into a `2xx`.
 */
export function verifyDelivery<T = unknown>(
  secret: string,
  rawBody: string | Buffer,
  headers: Record<string, string | string[] | undefined>,
): T {
  const webhook = new Webhook(secret);

  // The library wants plain string values. Node hands you `string[]` for a
  // header sent more than once, so flatten before passing them along.
  const flattened = Object.fromEntries(
    Object.entries(headers).flatMap(([key, value]) => {
      const single = Array.isArray(value) ? value[0] : value;
      return single === undefined ? [] : [[key.toLowerCase(), single]];
    }),
  );

  return webhook.verify(rawBody, flattened) as T;
}

/**
 * Run directly to verify the shared fixture:
 *
 *     node verify-with-library.ts
 *
 * The fixture's timestamp is fixed in the past, so a stock `verify()` would
 * reject it as stale no matter how correct the signature is. Signature
 * correctness is what this checks, so it is compared directly here. Your own
 * endpoint should keep the freshness check — see the notes in the repository
 * README on testing the two separately.
 */
if (import.meta.filename === process.argv[1]) {
  const { readFileSync } = await import("node:fs");
  const fixture = JSON.parse(
    readFileSync(new URL("../fixtures/signed-delivery.json", import.meta.url), "utf8"),
  );

  const webhook = new Webhook(fixture.secret);
  const computed = webhook.sign(
    fixture.headers["webhook-id"],
    new Date(Number(fixture.headers["webhook-timestamp"]) * 1000),
    fixture.body,
  );

  const expected = fixture.headers["webhook-signature"];

  console.log(`expected: ${expected}`);
  console.log(`computed: ${computed}`);
  console.log(computed === expected ? "\n✓ signature matches" : "\n✗ MISMATCH");

  process.exitCode = computed === expected ? 0 : 1;
}

/**
 * Verifying a LASSO webhook signature with no dependencies.
 *
 * This is the whole of what the `standardwebhooks` package does for the
 * verification path, written against `node:crypto` so you can read it, copy it,
 * and satisfy yourself that nothing surprising is happening. If you would
 * rather not maintain it, use the library instead — see
 * `verify-with-library.ts`. The two agree; `verify.test.ts` checks that they do.
 *
 * The signature covers `{webhook-id}.{webhook-timestamp}.{raw body}`, keyed by
 * the base64-decoded secret. Everything below is bookkeeping around that one
 * line.
 */

import { createHmac, timingSafeEqual } from "node:crypto";

/** Thrown for every reason a delivery may be rejected. */
export class WebhookVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WebhookVerificationError";
  }
}

const SECRET_PREFIX = "whsec_";
const SIGNATURE_VERSION = "v1";

/** HMAC-SHA256 is 32 bytes. A candidate of any other length cannot match. */
const DIGEST_BYTES = 32;

/**
 * How far `webhook-timestamp` may sit from your own clock. Five minutes either
 * side is what the Standard Webhooks libraries allow: long enough to absorb
 * ordinary clock drift, short enough that a captured request stops being
 * replayable quickly.
 */
export const DEFAULT_TOLERANCE_SECONDS = 5 * 60;

/** Header shape Node's HTTP servers and most frameworks produce. */
export type Headers = Record<string, string | string[] | undefined>;

export interface VerifyOptions {
  /** Defaults to {@link DEFAULT_TOLERANCE_SECONDS}. */
  toleranceSeconds?: number;
  /** Injectable clock. Present so tests need not depend on the current time. */
  now?: Date;
}

/**
 * Verify a delivery and return its parsed payload.
 *
 * `body` must be the **raw** request body, exactly as received — a `Buffer`, or
 * a string that has not been through a JSON round trip. If your framework
 * already parsed it, the bytes the signature covers are gone; see this
 * directory's README for how to keep them.
 *
 * Throws {@link WebhookVerificationError} on a bad signature, a missing header,
 * a stale timestamp, or an unusable secret. It never returns `false`: there is
 * no path where a caller can forget to check a result.
 */
export function verify<T = unknown>(
  secret: string,
  body: string | Buffer,
  headers: Headers,
  options: VerifyOptions = {},
): T {
  const id = requiredHeader(headers, "webhook-id");
  const timestamp = requiredHeader(headers, "webhook-timestamp");
  const signature = requiredHeader(headers, "webhook-signature");

  verifyTimestamp(timestamp, options);

  const bodyBytes = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  const expected = digest(secretKey(secret), id, timestamp, bodyBytes);

  if (!matches(signature, expected)) {
    throw new WebhookVerificationError("No matching signature found.");
  }

  // Parse only now. Doing it earlier would mean acting on the payload — even
  // just to reach a field — before knowing it came from LASSO.
  return JSON.parse(bodyBytes.toString("utf8")) as T;
}

/**
 * Produce the three headers that authenticate `body`.
 *
 * Sending is LASSO's job, so you need this only to sign test deliveries to your
 * own endpoint — which `sign.ts` does, and which is the one honest way to
 * confirm your handler rejects what it should.
 */
export function sign(
  secret: string,
  id: string,
  timestamp: number,
  body: string | Buffer,
): Record<string, string> {
  const bodyBytes = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
  const encoded = digest(
    secretKey(secret),
    id,
    String(timestamp),
    bodyBytes,
  ).toString("base64");

  return {
    "webhook-id": id,
    "webhook-timestamp": String(timestamp),
    "webhook-signature": `${SIGNATURE_VERSION},${encoded}`,
  };
}

/** The signature over `{id}.{timestamp}.{body}`, as raw bytes. */
function digest(
  key: Buffer,
  id: string,
  timestamp: string,
  body: Buffer,
): Buffer {
  // Concatenated as bytes rather than built as a string: the body may contain
  // any UTF-8, and going through a string risks a re-encoding that changes it.
  return createHmac("sha256", key)
    .update(Buffer.from(`${id}.${timestamp}.`, "utf8"))
    .update(body)
    .digest();
}

/**
 * The HMAC key: the secret with its prefix removed and base64 decoded.
 *
 * Validated strictly, because `Buffer.from(value, "base64")` silently discards
 * anything outside the base64 alphabet. A mistyped or free-form secret would
 * otherwise decode to arbitrary bytes and produce a signature that simply never
 * matches — a failure with no error attached to it, and a genuinely unpleasant
 * afternoon. Failing here says what is actually wrong.
 */
function secretKey(secret: string): Buffer {
  const encoded = secret.startsWith(SECRET_PREFIX)
    ? secret.slice(SECRET_PREFIX.length)
    : secret;

  // Restore padding the issuer may have trimmed, as the reference libraries do.
  const padded = encoded.padEnd(
    encoded.length + ((4 - (encoded.length % 4)) % 4),
    "=",
  );

  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(padded)) {
    throw new WebhookVerificationError(
      "Signing secret is not valid base64. Use it exactly as issued.",
    );
  }

  const key = Buffer.from(padded, "base64");

  if (key.length === 0) {
    throw new WebhookVerificationError("Signing secret is empty.");
  }

  return key;
}

/**
 * Whether any signature in the header matches.
 *
 * The header may carry several, space-separated, each tagged with its scheme
 * version. Accepting a match from any of them is what lets LASSO rotate a
 * secret, or introduce a `v2` alongside `v1`, without your endpoint dropping
 * deliveries in between. Versions you do not recognise are skipped rather than
 * treated as failures.
 */
function matches(header: string, expected: Buffer): boolean {
  let found = false;

  for (const candidate of header.split(" ")) {
    const separator = candidate.indexOf(",");

    if (separator === -1) continue;
    if (candidate.slice(0, separator) !== SIGNATURE_VERSION) continue;

    const supplied = Buffer.from(candidate.slice(separator + 1), "base64");

    // Length is checked first because `timingSafeEqual` throws on a mismatch,
    // and a length is not a secret.
    if (supplied.length !== DIGEST_BYTES) continue;

    // Constant time. A plain `===` would leak, through how long it takes to
    // fail, how much of a guessed signature was correct.
    if (timingSafeEqual(supplied, expected)) found = true;
  }

  return found;
}

/** Reject a delivery signed too long ago, or too far in the future. */
function verifyTimestamp(timestamp: string, options: VerifyOptions): void {
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  const now = Math.floor((options.now ?? new Date()).getTime() / 1000);
  const signed = Number(timestamp);

  if (!Number.isInteger(signed)) {
    throw new WebhookVerificationError(
      `Invalid webhook-timestamp: ${timestamp}`,
    );
  }

  if (signed < now - tolerance) {
    throw new WebhookVerificationError("Message timestamp too old.");
  }

  // Checked in both directions: our clock may be a little ahead of yours, and a
  // timestamp far in the future is a sign of something wrong either way.
  if (signed > now + tolerance) {
    throw new WebhookVerificationError("Message timestamp too new.");
  }
}

/**
 * Look a header up case-insensitively.
 *
 * HTTP header names are case-insensitive and different servers, proxies, and
 * frameworks normalise them differently. LASSO sends these three lowercase;
 * this makes that irrelevant. An array takes its first value, which is how
 * Node presents a header sent more than once.
 */
function requiredHeader(headers: Headers, name: string): string {
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== name) continue;

    const single = Array.isArray(value) ? value[0] : value;

    if (single !== undefined && single !== "") return single;
  }

  throw new WebhookVerificationError(`Missing required header: ${name}`);
}

/**
 * Send a correctly signed webhook to your own endpoint.
 *
 * LASSO does the signing in production, so this exists for one reason: to let
 * you exercise your handler before a real delivery arrives, including the cases
 * where it is supposed to say no. An endpoint that has only ever been shown a
 * valid request has not been tested.
 *
 *     # Sign a sample payload and POST it
 *     node sign.ts --url http://localhost:3000/webhooks/lasso --secret whsec_...
 *
 *     # Print a curl command instead of sending anything
 *     node sign.ts --secret whsec_... --curl
 *
 *     # Deliveries your handler must reject
 *     node sign.ts --url ... --secret ... --stale    # signed 15 minutes ago
 *     node sign.ts --url ... --secret ... --tamper   # body altered after signing
 *     node sign.ts --url ... --secret ... --unsigned # no signature headers
 *
 * The secret may also come from LASSO_WEBHOOK_SECRET. It only has to match
 * what your handler verifies with, so use a throwaway rather than the secret
 * LASSO issued you — the one in `fixtures/signed-delivery.json` will do. A
 * shell history is no place for a production secret.
 */

import { parseArgs } from "node:util";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

import { sign } from "./verify.ts";

const SAMPLE_PAYLOAD = {
  event: "test.event",
  id: 4815162342,
  data: "foobär",
};

/** How stale `--stale` makes a delivery: past any sane tolerance. */
const STALE_SECONDS = 15 * 60;

const { values } = parseArgs({
  options: {
    url: { type: "string" },
    secret: { type: "string" },
    "body-file": { type: "string" },
    id: { type: "string" },
    stale: { type: "boolean", default: false },
    tamper: { type: "boolean", default: false },
    unsigned: { type: "boolean", default: false },
    curl: { type: "boolean", default: false },
    help: { type: "boolean", default: false },
  },
});

if (values.help) {
  console.log(usage());
  process.exit(0);
}

const secret = values.secret ?? process.env.LASSO_WEBHOOK_SECRET;

if (!secret) {
  console.error("A --secret (or LASSO_WEBHOOK_SECRET) is required.\n");
  console.error(usage());
  process.exit(2);
}

if (!values.url && !values.curl) {
  console.error("Give a --url to POST to, or --curl to print a command.\n");
  console.error(usage());
  process.exit(2);
}

// Serialized once, here, and never re-serialized: these exact bytes are what
// gets signed and what gets sent. Doing it any other way is the mistake this
// whole repository is about.
const body = values["body-file"]
  ? readFileSync(values["body-file"], "utf8")
  : JSON.stringify(SAMPLE_PAYLOAD);

const id = values.id ?? `${datePrefix()}/${randomUUID().slice(0, 8)}.json`;
const timestamp = Math.floor(Date.now() / 1000) - (values.stale ? STALE_SECONDS : 0);

const headers: Record<string, string> = {
  "content-type": "application/json",
  ...(values.unsigned ? {} : sign(secret, id, timestamp, body)),
};

// Signed above, altered here. The signature stays valid for the original bytes,
// which is exactly the forgery a verifying endpoint has to catch.
const sent = values.tamper ? tamper(body) : body;

if (values.curl) {
  console.log(curl(values.url ?? "https://example.invalid/webhooks/lasso", headers, sent));
  process.exit(0);
}

const response = await fetch(values.url!, { method: "POST", headers, body: sent });
const text = await response.text();

console.log(`POST ${values.url}`);
for (const [name, value] of Object.entries(headers)) {
  console.log(`  ${name}: ${value}`);
}
console.log(`\nbody: ${sent}`);
console.log(`\n→ ${response.status} ${response.statusText}`);
if (text) console.log(text);

// A rejection is the expected outcome for the deliberately-bad modes, so report
// on whether the endpoint did the right thing rather than on the status alone.
const shouldReject = values.stale || values.tamper || values.unsigned;
const rejected = !response.ok;

if (shouldReject) {
  console.log(
    rejected
      ? "\n✓ Correctly rejected."
      : "\n✗ This delivery should NOT have been accepted. Check your verification.",
  );
  process.exitCode = rejected ? 0 : 1;
} else {
  console.log(rejected ? "\n✗ A valid delivery was rejected." : "\n✓ Accepted.");
  process.exitCode = rejected ? 1 : 0;
}

/** Change the body without re-signing it. */
function tamper(original: string): string {
  const parsed = JSON.parse(original) as Record<string, unknown>;
  return JSON.stringify({ ...parsed, data: "tampered" });
}

/** `webhook-id` values look like this; nothing depends on the shape. */
function datePrefix(): string {
  return new Date().toISOString().slice(0, 10).replaceAll("-", "/");
}

function curl(url: string, headers: Record<string, string>, body: string): string {
  const flags = Object.entries(headers).map(
    ([name, value]) => `  -H ${shellQuote(`${name}: ${value}`)}`,
  );

  return [
    `curl -sS -X POST ${shellQuote(url)}`,
    ...flags,
    `  --data-binary ${shellQuote(body)}`,
  ].join(" \\\n");
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function usage(): string {
  return [
    "Usage: node sign.ts --secret whsec_... [--url URL | --curl] [options]",
    "",
    "  --url URL        POST the signed delivery here",
    "  --curl           print a curl command instead of sending",
    "  --secret SECRET  signing secret (or set LASSO_WEBHOOK_SECRET)",
    "  --body-file PATH JSON body to send, instead of the built-in sample",
    "  --id ID          webhook-id to use, instead of a generated one",
    "  --stale          sign with a 15-minute-old timestamp (must be rejected)",
    "  --tamper         alter the body after signing (must be rejected)",
    "  --unsigned       send no signature headers at all (must be rejected)",
  ].join("\n");
}

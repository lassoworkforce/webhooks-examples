/**
 * A complete Express endpoint for signed LASSO webhooks.
 *
 *     npm install
 *     LASSO_WEBHOOK_SECRET=whsec_... node server-express.ts
 *
 * Then, from another shell:
 *
 *     node sign.ts --url http://localhost:3000/webhooks/lasso --secret whsec_...
 *     node sign.ts --url http://localhost:3000/webhooks/lasso --secret whsec_... --tamper
 *
 * The cryptography is in `verify.ts`. What this file is actually about is the
 * one line that makes it possible — `express.raw()` on the webhook route — and
 * the shape of a handler around it. Swap `verify` for the library version in
 * `verify-with-library.ts` and nothing else here changes.
 */

import express, { type Request, type Response } from "express";

import { verify, WebhookVerificationError } from "./verify.ts";

const PORT = Number(process.env.PORT ?? 3000);

/**
 * Every secret this endpoint will accept, newest first.
 *
 * A list rather than a single value so that a rotation is not an outage: keep
 * accepting the old secret until you have seen a delivery signed with the new
 * one, then drop it. Supply as a comma-separated LASSO_WEBHOOK_SECRET.
 */
const SECRETS: string[] = (process.env.LASSO_WEBHOOK_SECRET ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

if (SECRETS.length === 0) {
  console.error("Set LASSO_WEBHOOK_SECRET (comma-separated to accept several).");
  process.exit(2);
}

const app = express();

/**
 * A JSON body parser is the usual default for an API, and it is the reason
 * webhook verification fails. By the time a parser has run, the bytes the
 * signature covers are gone, and the parsed object will not re-serialize back
 * into them. So it is mounted *after* the webhook route below, where it cannot
 * reach it.
 *
 * If you already have `express.json()` mounted globally, do not move it — give
 * the webhook route its own `express.raw()`, which takes precedence for that
 * path, or configure the parser with a `verify` callback that stashes the raw
 * buffer on the request.
 */
app.post(
  "/webhooks/lasso",
  // The line that matters. `type: "*/*"` rather than "application/json" so the
  // body still arrives as a Buffer if the content type is ever anything else —
  // when it does not match, Express hands you an empty object instead, and the
  // failure looks like a signature problem rather than a parsing one.
  express.raw({ type: "*/*", limit: "5mb" }),
  handleWebhook,
);

app.use(express.json());

/** Ids already handled, so a retried delivery is not processed twice. */
const handled = new Set<string>();

function handleWebhook(request: Request, response: Response): void {
  // A Buffer because of `express.raw()` above. If this is not a Buffer, some
  // other middleware got to the body first.
  const rawBody: Buffer = request.body;

  let payload: WebhookPayload;

  try {
    payload = verifyWithAnySecret(rawBody, request.headers);
  } catch (error) {
    if (error instanceof WebhookVerificationError) {
      // Answer 400, not 2xx. A signature that does not verify means the secret,
      // the body handling, or the request's authenticity is wrong, and quietly
      // accepting it hides all three.
      console.warn(
        `Rejected delivery ${request.headers["webhook-id"]}: ${error.message}`,
      );
      response.status(400).json({ error: error.message });
      return;
    }

    throw error;
  }

  // Verified. Everything from here is ordinary application code.
  const id = request.headers["webhook-id"] as string;

  if (handled.has(id)) {
    // A duplicate is a success: it means we already have this one. Answering
    // anything else invites yet another retry. In a real service this check
    // belongs in shared storage — a database row keyed on `webhook-id`, or a
    // unique constraint — since retries may land on a different instance.
    console.log(`Duplicate delivery ${id}, already handled.`);
    response.status(200).json({ status: "duplicate" });
    return;
  }

  handled.add(id);

  console.log(`Accepted ${id}: ${payload.event} carrying ${payload.data}`);

  // Answer now and do the work afterwards. A slow handler is treated as a
  // failed delivery and retried, so anything that might be slow — a database
  // write, an outbound call — belongs on a queue rather than in this function.
  response.status(202).json({ status: "accepted" });
}

/**
 * Verify against each configured secret in turn, returning the payload from
 * whichever one accepts the delivery.
 */
function verifyWithAnySecret(rawBody: Buffer, headers: Request["headers"]): WebhookPayload {
  let lastError: WebhookVerificationError | undefined;

  for (const secret of SECRETS) {
    try {
      return verify<WebhookPayload>(secret, rawBody, headers);
    } catch (error) {
      if (!(error instanceof WebhookVerificationError)) throw error;
      lastError = error;
    }
  }

  throw lastError ?? new WebhookVerificationError("No signing secret configured.");
}

/**
 * Payloads are yours to model; this is only enough to make the example
 * concrete. `verify` returns `unknown` unless you tell it otherwise, which is
 * deliberate: a verified signature proves the payload came from LASSO, not that
 * it has the shape this version of your code expects. Validate it as you would
 * any other input — with Zod, or by hand.
 */
interface WebhookPayload {
  event: string;
  id: number;
  data: string;
}

app.listen(PORT, () => {
  console.log(`Listening on http://localhost:${PORT}/webhooks/lasso`);
  console.log(`Accepting ${SECRETS.length} signing secret(s).`);
});

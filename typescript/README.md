# Verifying LASSO webhooks in TypeScript

```bash
npm install
npm test          # verify both implementations against the shared fixture
npm run fixture   # check the fixture with the reference library alone
```

| File | What it is |
| --- | --- |
| [`verify-with-library.ts`](verify-with-library.ts) | Verification using the `standardwebhooks` package. Start here. |
| [`verify.ts`](verify.ts) | The same check with no dependencies, against `node:crypto`. Read and copy. |
| [`server-express.ts`](server-express.ts) | A complete Express endpoint: raw body, rotation, deduplication, status codes. |
| [`sign.ts`](sign.ts) | Sends signed test deliveries to your endpoint, including ones it must reject. |
| [`verify.test.ts`](verify.test.ts) | The failure cases. Copy these along with `verify.ts`. |

These files are TypeScript that Node runs directly — it strips the type
annotations, so there is no build step and nothing generated to keep in sync.
Node 22.18+ or 24+ run them as-is; on Node 22.6–22.17 add
`--experimental-strip-types`. For plain JavaScript, delete the type annotations:
nothing here depends on TypeScript beyond them.

## The short version

```ts
import { Webhook } from "standardwebhooks";

// Load your signing secret however your application loads secrets.
const wh = new Webhook("PUT_YOUR_SECRET_HERE");
const payload = wh.verify(rawBody, headers); // throws if it does not verify
```

That is the whole integration. The difficulty is never this call — it is making
sure `rawBody` is the bytes that arrived.

## Getting the raw body

The signature covers the exact bytes LASSO sent. A JSON body parser consumes
them and hands you an object, and re-serializing that object does not reliably
reproduce them. So the raw body has to be captured before anything parses it.

This is worth being precise about, because the failure is deceptive: for most
payloads `JSON.stringify(JSON.parse(body))` *does* reproduce the original bytes,
so a handler that re-serializes appears to work. Then a payload arrives carrying
an integer larger than `Number.MAX_SAFE_INTEGER`, or a decimal written `7.50`,
and that one delivery fails while every other keeps working. There is a test for
this in [`verify.test.ts`](verify.test.ts).

**Express** — give the webhook route its own `express.raw()`:

```ts
app.post(
  "/webhooks/lasso",
  express.raw({ type: "*/*" }), // req.body is now a Buffer
  handler,
);
```

Route-level middleware takes precedence, so this works even with
`express.json()` mounted globally — no need to rearrange an existing app. Use
`type: "*/*"` rather than `"application/json"`: when the type does not match,
Express hands you an empty object instead, and the resulting failure looks like
a signature problem rather than a parsing one. See
[`server-express.ts`](server-express.ts).

If you would rather keep one global parser, capture the buffer as it goes past:

```ts
app.use(express.json({
  verify: (req, _res, buf) => { (req as any).rawBody = buf; },
}));
```

**Fastify** — add a content type parser that leaves the body alone:

```ts
fastify.addContentTypeParser(
  "application/json",
  { parseAs: "buffer" },
  (_req, body, done) => done(null, body),
);
```

Or scope it to the route with `config` if other routes need parsed JSON.

**Next.js** (App Router) — `await request.text()` gives you the raw body, and
the route must not be statically optimized:

```ts
export async function POST(request: Request) {
  const rawBody = await request.text();
  const headers = Object.fromEntries(request.headers);
  // verify, then parse
}
```

On the older Pages Router, set `export const config = { api: { bodyParser: false } }`
and read the stream yourself.

**NestJS** — create the app with `rawBody: true`
(`NestFactory.create(AppModule, { rawBody: true })`) and read `request.rawBody`.

**Plain `node:http`** — concatenate the chunks:

```ts
const chunks: Buffer[] = [];
for await (const chunk of request) chunks.push(chunk);
const rawBody = Buffer.concat(chunks);
```

**AWS Lambda / API Gateway** — the body arrives as a string on `event.body`, but
if the platform judged it binary it is base64 encoded, and the signature covers
the decoded bytes:

```ts
const rawBody = event.isBase64Encoded
  ? Buffer.from(event.body, "base64")
  : Buffer.from(event.body ?? "", "utf8");
```

Skipping that check produces signatures that verify most of the time and fail
whenever the encoding flips.

## Which implementation to use

Use the library. It is the reference implementation of the specification LASSO
signs against, which means the verification is not code you own, review, or
maintain.

[`verify.ts`](verify.ts) exists for when a dependency is not worth it — an
audited service, a constrained runtime, or a policy about third-party packages.
It is about a hundred lines of `node:crypto` and is tested against the same
fixture as the library path, so the two are known to agree. Two things in it are worth
keeping if you adapt it: `timingSafeEqual` rather than `===`, and the strict
base64 check on the secret, which turns a mistyped secret into an error instead
of a signature that silently never matches.

## Testing your endpoint

```bash
# A valid delivery
node sign.ts --url http://localhost:3000/webhooks/lasso --secret whsec_...

# Deliveries your handler must reject
node sign.ts --url ... --secret ... --tamper    # body changed after signing
node sign.ts --url ... --secret ... --stale     # signed 15 minutes ago
node sign.ts --url ... --secret ... --unsigned  # no signature headers

# Print a curl command instead of sending
node sign.ts --secret whsec_... --curl
```

The three rejection modes report whether your endpoint did the right thing, and
exit non-zero when it accepted something it should have refused — so they work
as a check in CI. An endpoint that has only ever been shown a valid request has
not been tested.

`--secret` also reads from `LASSO_WEBHOOK_SECRET`. For local testing the signer
and your handler only have to agree, so use a throwaway rather than the secret
LASSO issued you — the one in
[`fixtures/signed-delivery.json`](../fixtures/signed-delivery.json) will do.
Shell history is no place for a production secret.

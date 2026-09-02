# Verifying LASSO webhooks

LASSO signs the custom webhooks it sends you. The signature proves the request
came from LASSO and that nobody altered it on the way, so you can act on a
payload without first calling back to confirm it.

Signatures follow [Standard Webhooks](https://www.standardwebhooks.com/), an open
specification with ready-made verification libraries for most languages. In most
cases verifying is three lines of code and one dependency. This repository shows
that path, the same thing written out with no dependency at all, and working
servers in both languages — because the mistake that breaks verification is
almost never the cryptography, it is how your framework hands you the request
body.

| I want to | Go to |
| --- | --- |
| Verify in TypeScript or JavaScript | [`typescript/`](typescript/) |
| Verify in Python | [`python/`](python/) |
| Get a signing secret | [Your signing secret](#your-signing-secret) |
| Test my endpoint before a real delivery | [Testing before you go live](#testing-before-you-go-live) |
| Work out why a signature will not verify | [Troubleshooting](#troubleshooting) |

## What arrives

A signed delivery is an ordinary `POST` with your payload as the body and three
extra headers:

| Header | Example | What it is |
| --- | --- | --- |
| `webhook-id` | `2026/09/02/61bd0a1e.json` | Unique id for this message. Stable across retries — use it to discard duplicates. |
| `webhook-timestamp` | `1788350400` | When we signed the request, in Unix seconds (UTC). Use it to reject replays. |
| `webhook-signature` | `v1,HVtofnqyefTH5krZ/...` | One or more space-separated signatures, each prefixed with its scheme version. |

HTTP header names are case-insensitive. We send them lowercase; look them up
case-insensitively rather than relying on that.

## Quickstart

Install a Standard Webhooks library and hand it the raw body plus the headers.

**TypeScript / JavaScript** — [full example](typescript/verify-with-library.ts)

```bash
npm install standardwebhooks
```

```ts
import { Webhook } from "standardwebhooks";

// Load your signing secret however your application loads secrets.
const wh = new Webhook("PUT_YOUR_SECRET_HERE");

// `rawBody` must be the unparsed request body, as a string or Buffer.
const payload = wh.verify(rawBody, {
  "webhook-id": headers["webhook-id"],
  "webhook-timestamp": headers["webhook-timestamp"],
  "webhook-signature": headers["webhook-signature"],
});
```

**Python** — [full example](python/verify_with_library.py)

```bash
pip install standardwebhooks
```

```python
from standardwebhooks.webhooks import Webhook

# Load your signing secret however your application loads secrets.
wh = Webhook("PUT_YOUR_SECRET_HERE")

# `raw_body` must be the unparsed request body.
payload = wh.verify(raw_body, dict(request.headers))
```

`verify` raises on a bad signature, a missing header, and a stale timestamp, and
returns the parsed payload when everything checks out. A raised exception should
become a `400`; see [Answering the request](#answering-the-request).

Both libraries accept the secret with or without the `whsec_` prefix.

## Your signing secret

LASSO generates the signing secret and provides it to you. Custom webhooks are
given one by default, so yours is normally signed already and what you need in
order to start verifying is the secret itself. Ask LASSO for it, and you will be
given a value of the form `whsec_` followed by `base64` encoded data.

Use it exactly as issued. It is key material rather than a password — the value
is decoded to produce the HMAC key — so there is nothing in it to shorten,
re-encode, or retype, and there is no need to generate one of your own.

If a secret needs changing, ask LASSO to rotate it — see [Rules that
matter](#rules-that-matter) for accepting both values while a rotation reaches
every delivery.

## Verifying without a dependency

If adding a dependency is more trouble than it is worth, the same check is about
a hundred lines against your standard library:

- [`typescript/verify.ts`](typescript/verify.ts) — `node:crypto`, no packages
- [`python/verify.py`](python/verify.py) — `hmac`, `hashlib`, `base64`

Both are written to be read and copied, and both are tested against the shared
fixture in [`fixtures/`](fixtures/) alongside the library implementations, so the
two paths are known to agree. If you copy one, copy its tests too.

Each file documents the signature construction it implements, and the
[specification](https://www.standardwebhooks.com/) is the normative description
of it.

## Rules that matter

Everything here is a real way verification goes wrong.

**Verify the raw body, before parsing.** Frameworks that helpfully parse JSON for
you have already thrown away the bytes the signature covers. Reading the parsed
object and re-serializing it will not reproduce them: key order, whitespace, and
number formatting are all free to differ. Getting at the raw body is
framework-specific and is the single thing most worth checking first — the
[`typescript/`](typescript/) and [`python/`](python/) guides show how for
Express, Fastify, Next.js, Flask, FastAPI, Django, and AWS Lambda.

**Compare in constant time.** Use `crypto.timingSafeEqual`, `hmac.compare_digest`,
or your language's equivalent. A plain `==` on the signature leaks, through how
long it takes to fail, how much of a guess was right.

**Reject stale timestamps.** Without a freshness check, anyone who captures one
signed request can replay it forever. Five minutes either side is the usual
allowance and what the libraries default to. Allow for clocks in both
directions: our clock may be slightly ahead of yours.

**Expect more than one signature.** `webhook-signature` may carry several,
space-separated, and versions other than `v1` may appear in future. Accept the
delivery if *any* signature you understand matches, and ignore versions you do
not recognise. This is what lets a secret be rotated without dropping
deliveries, and it is why you should loop rather than compare the whole header.

**Deduplicate on `webhook-id`.** A delivery may be retried — because your
endpoint was slow, returned an error, or the response was lost after you had
already processed it. Retries carry the same `webhook-id` with a *fresh*
timestamp and signature, so key your idempotency on the id alone. Treat the id
as an opaque string: it can contain `/` and `.`, so it is not safe to use
unescaped as a filename or path segment.

**During rotation, try every secret you hold.** When a secret is rotated, keep
accepting the old one until deliveries signed with the new one arrive, and
verify against each in turn.

**Keep the secret out of your logs.** Log `webhook-id` when a delivery fails to
verify. It identifies the delivery to us, and discloses nothing.

## Answering the request

Return `2xx` once you have verified and accepted the delivery, and do it
promptly — queue the slow part of your work rather than finishing it before you
reply. Anything else is treated as a failed delivery and may be retried.

Answer `400` when a signature does not verify. Do not return `2xx`: a signature
that never verifies means something is wrong with the secret, the body handling,
or the request's authenticity, and silently swallowing it hides all three.

## Testing before you go live

**Against the fixture.** [`fixtures/signed-delivery.json`](fixtures/signed-delivery.json)
is a complete signed delivery — secret, headers, and body — with a signature
independently reproduced by the Standard Webhooks reference implementation. If
your code accepts it, your signature computation is right. Its timestamp is
fixed in the past deliberately, so a freshness check will reject it: test
signature correctness and freshness as two separate cases, the way the examples
here do.

**Against your own endpoint.** Each language ships a signer that sends a
correctly signed request to a URL you choose, so you can exercise your handler
without waiting on a real delivery:

```bash
# TypeScript
node typescript/sign.ts --url http://localhost:3000/webhooks/lasso --secret whsec_...

# Python
python python/sign.py --url http://localhost:8000/webhooks/lasso --secret whsec_...
```

Both can also emit `curl`-ready output, and both accept `--stale` and
`--tamper` so you can confirm your handler *rejects* what it should. An endpoint
that has only ever been shown a valid request has not been tested.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| Deliveries arrive but carry no signature headers | That webhook is not signed. A webhook may predate signing or have it switched off. See [Your signing secret](#your-signing-secret). |
| Signature never matches, and the fixture fails too | The secret is being used as raw ASCII instead of base64-decoded, or the `whsec_` prefix was left in place before decoding. |
| Fixture passes, real deliveries fail | You are verifying a re-serialized body. Capture the raw bytes before any JSON parsing. |
| Fails only for some payloads | Non-ASCII text. The signature covers UTF-8 bytes; the fixture payload contains `ä` for exactly this reason. Encode as UTF-8, and do not measure the body in characters. |
| Worked, then broke everywhere at once | A rotated secret. Verify against every secret you currently hold. |
| Intermittent failures under load | The body was consumed or mutated by middleware before your handler saw it, or you are reading a stream twice. |
| "Timestamp too old" on deliveries that just arrived | Your server clock has drifted, or you are comparing against local time instead of UTC. |
| Everything verifies but you process some events twice | Missing deduplication on `webhook-id`; retries are expected. |

If you are still stuck, contact LASSO support with the `webhook-id` of a
delivery that failed and the time you received it. Do not send us your secret.

## What is stable, and what is not

You can rely on the signing scheme itself: the three headers, the way the signed
content is assembled, HMAC-SHA256, and base64. It is a published specification
and a change to it would be announced.

Do not build on the body's exact formatting. It is compact JSON today, but
whitespace, key order, and number formatting may change at any time — which
costs you nothing as long as you verify the bytes as received.

## License

MIT — see [LICENSE](LICENSE). Copy anything here into your own codebase.

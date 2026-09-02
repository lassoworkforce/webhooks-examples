# Verifying LASSO webhooks in Python

```bash
pip install -r requirements.txt
pytest                          # verify both implementations against the shared fixture
python verify_with_library.py   # check the fixture with the reference library alone
```

| File | What it is |
| --- | --- |
| [`verify_with_library.py`](verify_with_library.py) | Verification using the `standardwebhooks` package. Start here. |
| [`verify.py`](verify.py) | The same check with no dependencies at all. Read and copy. |
| [`server_flask.py`](server_flask.py) | A complete Flask endpoint: raw body, rotation, deduplication, status codes. |
| [`server_fastapi.py`](server_fastapi.py) | The same endpoint in FastAPI. |
| [`sign.py`](sign.py) | Sends signed test deliveries to your endpoint, including ones it must reject. |
| [`test_verify.py`](test_verify.py) | The failure cases. Copy these along with `verify.py`. |

Python 3.12 or newer. [`verify.py`](verify.py) and [`sign.py`](sign.py) need
nothing installed — they are standard library only.

## The short version

```python
from standardwebhooks.webhooks import Webhook

# Load your signing secret however your application loads secrets.
wh = Webhook("PUT_YOUR_SECRET_HERE")
payload = wh.verify(raw_body, dict(request.headers))  # raises if it does not verify
```

That is the whole integration. The difficulty is never this call — it is making
sure `raw_body` is the bytes that arrived.

## Getting the raw body

The signature covers the exact bytes LASSO sent. A JSON body parser consumes
them and hands you a `dict`, and re-serializing that `dict` does not reproduce
them: `json.dumps` escapes non-ASCII and puts a space after every separator, so
its output differs from the wire format immediately.

Matching those arguments is not a fix either. Even with
`ensure_ascii=False, separators=(",", ":")`, a decimal that arrived as `7.50`
comes back as `7.5`, and that one delivery fails while every other keeps
working — an intermittent failure you cannot reproduce. Both cases are tested in
[`test_verify.py`](test_verify.py). Verify the bytes as received.

**Flask** — `request.get_data()`:

```python
@app.post("/webhooks/lasso")
def webhook():
    raw_body = request.get_data()   # bytes, exactly as sent
    payload = verify(secret, raw_body, request.headers)
```

Flask does not parse a JSON body until you ask it to, so this is safe by
default. The mistake is reaching for `request.json` and re-serializing it. See
[`server_flask.py`](server_flask.py).

**FastAPI / Starlette** — take a bare `Request` and `await request.body()`:

```python
@app.post("/webhooks/lasso")
async def webhook(request: Request):
    raw_body = await request.body()
    payload = verify(secret, raw_body, request.headers)
```

Declaring a Pydantic model parameter instead is the usual FastAPI style, and it
is what breaks verification — FastAPI parses the body to build the model. Take
the `Request`, verify, then validate the payload with your model afterwards. See
[`server_fastapi.py`](server_fastapi.py).

**Django** — `request.body`:

```python
@csrf_exempt   # the signature is the authentication; CSRF does not apply
def webhook(request):
    payload = verify(secret, request.body, request.headers)
```

`request.body` is the raw bytes, but reading `request.POST` first consumes the
stream, so do not touch it. `@csrf_exempt` is required: LASSO has no CSRF token
to send, and the signature is what authenticates the request.

**Django REST Framework** — `request.body` still works, but a parser may have
run already. `request.data` is not usable for verification.

**AWS Lambda / API Gateway** — the body arrives as a string on `event["body"]`,
but if the platform judged it binary it is base64 encoded, and the signature
covers the decoded bytes:

```python
raw_body = (
    base64.b64decode(event["body"])
    if event.get("isBase64Encoded")
    else (event.get("body") or "").encode("utf-8")
)
```

Skipping that check produces signatures that verify most of the time and fail
whenever the encoding flips.

## Which implementation to use

Use the library. It is the reference implementation of the specification LASSO
signs against, which means the verification is not code you own, review, or
maintain.

[`verify.py`](verify.py) exists for when a dependency is not worth it — an
audited service, a constrained runtime, or a policy about third-party packages.
It is about a hundred lines of `hmac` and `hashlib` and is tested against the
same fixture as the library path, so the two are known to agree. Two things in it are
worth keeping if you adapt it: `hmac.compare_digest` rather than `==`, and
`base64.b64decode(..., validate=True)` on the secret, which turns a mistyped
secret into an error instead of a signature that silently never matches.

## Testing your endpoint

```bash
# A valid delivery
python sign.py --url http://localhost:8000/webhooks/lasso --secret whsec_...

# Deliveries your handler must reject
python sign.py --url ... --secret ... --tamper    # body changed after signing
python sign.py --url ... --secret ... --stale     # signed 15 minutes ago
python sign.py --url ... --secret ... --unsigned  # no signature headers

# Print a curl command instead of sending
python sign.py --secret whsec_... --curl
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

# PayGate

Multi-tenant SMS payment verification server for **bKash** and **Nagad**.

A merchant phone (Android SMS forwarder) posts incoming payment SMS to PayGate. PayGate parses
the amount, sender and TrxID, matches it against the right SaaS tenant's pending checkout, locks
the TrxID exactly once, and delivers a signed webhook with retries.

```
SaaS app ──POST /api/payments──▶ PayGate ──hosted /pay/:id──▶ Customer pays
                                     ▲                              │
                                     │                              ▼
                              /webhook/sms/:token  ◀──  Android SMS forwarder
                                     │
                                     └── HMAC-signed payment.succeeded ──▶ SaaS webhook
```

## Features

- **Multi-tenant** — unlimited apps, each with its own `pk_` API key, `whsec_` signing secret,
  webhook URL and linked bKash/Nagad devices.
- **Hosted checkout** — `/pay/:id` shows both merchant numbers, copies to clipboard, polls every
  4 seconds and redirects to your `return_url` on success.
- **TrxID hijack protection** — an SMS is locked to a payment exactly once inside a SQLite
  `IMMEDIATE` transaction. Matching requires the **exact amount** and, when the payment pins one,
  the **exact sender number**. Duplicate TrxIDs are rejected globally.
- **Reliable webhooks** — transactional outbox + recursive `setTimeout` worker, HMAC-SHA256
  signatures, exponential backoff with jitter, lease recovery after crashes.
- **Flexible SMS ingestion** — JSON, `application/x-www-form-urlencoded`, raw `text/plain`, or
  query-string payloads; explicit fields are preferred, SMS text parsing is the fallback.
- **Single file, two dependencies** — Express 5 + better-sqlite3 (WAL mode).

## Requirements

- Node.js **20+**
- A build toolchain for `better-sqlite3` if no prebuilt binary is available for your platform.

## Quick start

```bash
npm install
cp .env.example .env          # Windows: copy .env.example .env
# edit .env and set ADMIN_API_KEY + PUBLIC_BASE_URL
npm start
```

The server prints a generated admin key when `ADMIN_API_KEY` is unset in development.
Check it is alive:

```bash
curl http://localhost:3000/healthz
```

### 1. Register a device

```bash
curl -X POST http://localhost:3000/api/admin/devices \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"bKash counter 1","type":"bkash","phone_number":"01711111111"}'
```

The response contains `webhook_url`. Configure your SMS forwarder to POST to it.

### 2. Register an app

```bash
curl -X POST http://localhost:3000/api/admin/apps \
  -H "X-Admin-Key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
        "name": "Shop A",
        "webhook_url": "https://shop-a.example.com/paygate/webhook",
        "return_url": "https://shop-a.example.com/thanks",
        "bkash_device_id": 1,
        "nagad_device_id": 2
      }'
```

Store the returned `pk_key` and `webhook_secret` on your side.

### 3. Create a payment

```bash
curl -X POST http://localhost:3000/api/payments \
  -H "Authorization: Bearer pk_..." \
  -H "Content-Type: application/json" \
  -d '{"amount": 500, "metadata": {"order_id": "A-1001"}}'
```

Redirect the customer to `checkout_url`. When the SMS arrives, the payment flips to `success`
and your webhook receives `payment.succeeded`.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `NODE_ENV` | `development` | `production` requires `ADMIN_API_KEY`. |
| `HOST` / `PORT` | `0.0.0.0` / `3000` | Listen address. |
| `PUBLIC_BASE_URL` | _(request origin)_ | Public origin used in checkout links. |
| `DATABASE_PATH` | `./data/paygate.db` | SQLite file (WAL). |
| `ADMIN_API_KEY` | _(generated in dev)_ | Auth for `/api/admin/*`. |
| `TRUST_PROXY` | `false` | Express trust-proxy setting (use `1` behind nginx). |
| `PAYMENT_TTL_SECONDS` | `900` | Default checkout lifetime. |
| `MAX_PAYMENT_AMOUNT_BDT` | `500000` | Upper amount bound. |
| `WEBHOOK_TIMEOUT_MS` | `10000` | Per-attempt timeout. |
| `WEBHOOK_MAX_ATTEMPTS` | `10` | Attempts before the event is marked `failed`. |
| `WEBHOOK_BATCH_SIZE` | `20` | Rows drained per tick. |
| `WEBHOOK_CONCURRENCY` | `5` | Parallel deliveries. |
| `WEBHOOK_WORKER_IDLE_MS` | `1000` | Idle poll interval. |
| `WEBHOOK_ALLOW_PRIVATE_URLS` | `true` outside prod | Allow localhost/private webhook targets. |
| `RATE_LIMIT_PUBLIC_PER_MIN` | `240` | Per-IP limit for public polling. |
| `RATE_LIMIT_WEBHOOK_PER_MIN` | `600` | Per-IP limit for SMS ingestion. |

## API

Admin requests use `X-Admin-Key: <ADMIN_API_KEY>` (or a Bearer token). App requests use
`Authorization: Bearer pk_...` (or `X-Api-Key`).

### Admin

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/admin/devices` | Create a device, returns `webhook_token`/`webhook_url`. |
| `GET` | `/api/admin/devices` | List devices. |
| `PATCH` | `/api/admin/devices/:id` | Rename, change number, toggle `active`, `rotate_token`. |
| `DELETE` | `/api/admin/devices/:id` | Delete (requires `?force=1` when linked). |
| `POST` | `/api/admin/apps` | Create an app, returns `pk_key` + `webhook_secret`. |
| `GET` | `/api/admin/apps` | List apps. |
| `PATCH` | `/api/admin/apps/:id` | Update links/URLs, toggle `active`, `rotate_keys`. |
| `DELETE` | `/api/admin/apps/:id` | Delete app + data (requires `?force=1`). |
| `GET` | `/api/admin/payments` | All payments (`status`, `limit`, `offset`). |
| `GET` | `/api/admin/sms` | SMS payments (`status=unmatched`). |
| `GET` | `/api/admin/sms/events` | Raw ingestion log incl. unparseable SMS (`status`). |
| `POST` | `/api/admin/sms/:id/match` | Manually settle an unmatched SMS (`payment_id`). |
| `GET` | `/api/admin/outbox` | Inspect webhook deliveries (`status`). |
| `POST` | `/api/admin/outbox/:id/retry` | Re-queue a `failed`/`delivered` event. |
| `GET` | `/api/admin/stats` | Counters. |

### App

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/payments` | Create a checkout. Body: `amount`, optional `return_url`, `sender_number`, `metadata`, `expires_in`. |
| `GET` | `/api/payments` | List this app's payments (`status`, `limit`, `offset`). |
| `GET` | `/api/payments/:id` | Fetch one payment. |
| `POST` | `/api/payments/:id/cancel` | Cancel a pending payment. |

Amounts are BDT with at most 2 decimals; internally they are stored as integer **poisha**.

### Public

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/pay/:id` | Hosted checkout page. |
| `GET` | `/api/public/payments/:id` | Poll status (no secrets, CORS enabled). |

### SMS ingestion

```
POST /webhook/sms/:token
GET  /webhook/sms/:token?message=...&sender=...
```

Accepted shapes (all optional except a parsable message):

```jsonc
// JSON
{"message": "You have received Tk 500.00 from 01712345678. TrxID ABC1234567."}
// Explicit fields win over text parsing
{"text": "...", "trx_id": "ABC1234567", "amount": "500.00", "sender": "01712345678"}
// Form encoded
message=You+have+received+Tk+500.00+from+01712345678.+TrxID+ABC1234567
// Raw text/plain SMS body
```

Responses are always fast and idempotent:

```json
{"ok": true, "matched": true, "payment_id": "pay_...", "status": "success", "trx_id": "ABC1234567"}
{"ok": true, "matched": false, "reason": "no_matching_payment", "trx_id": "..."}
{"ok": true, "duplicate": true, "reason": "trx_id_already_recorded"}
```

The same payload replayed is de-duplicated by a per-device hash; the same TrxID from any device
is rejected globally.

## Webhooks

`payment.succeeded` and `payment.expired` are delivered to the app's `webhook_url`:

```json
{
  "id": "evt_...",
  "object": "event",
  "type": "payment.succeeded",
  "created_at": "2026-01-01T00:00:00.000Z",
  "data": {
    "id": "pay_...",
    "object": "payment",
    "amount": 500,
    "amount_poisha": 50000,
    "currency": "BDT",
    "status": "success",
    "trx_id": "ABC1234567",
    "sender_number": "01712345678",
    "device_type": "bkash",
    "metadata": {"order_id": "A-1001"},
    "created_at": "...",
    "paid_at": "...",
    "checkout_url": "https://pay.example.com/pay/pay_..."
  }
}
```

Headers:

```
X-PayGate-Signature: sha256=<hex hmac>
X-PayGate-Timestamp: <unix seconds>
X-PayGate-Event: payment.succeeded
X-PayGate-Event-Id: evt_...
X-PayGate-Payment-Id: pay_...
X-PayGate-Delivery-Attempt: 1
```

The signed string is `` `${X-PayGate-Timestamp}.${rawRequestBody}` `` using HMAC-SHA256 and the
app's `whsec_` secret. Verify against the **raw** body before JSON parsing, reject timestamps
older than ~5 minutes, and reply `2xx` quickly. Non-2xx responses and timeouts are retried with
exponential backoff (10s → 12h, 10 attempts by default).

```js
const crypto = require('node:crypto');

function verify(rawBody, headers, secret) {
  const timestamp = headers['x-paygate-timestamp'];
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.${rawBody}`)
    .digest('hex');
  const received = String(headers['x-paygate-signature'] || '').replace(/^sha256=/, '');
  return (
    Math.abs(Date.now() / 1000 - Number(timestamp)) < 300 &&
    received.length === expected.length &&
    crypto.timingSafeEqual(Buffer.from(received), Buffer.from(expected))
  );
}
```

## Matching rules

For an incoming SMS, PayGate selects the **oldest** pending payment where:

1. the payment's app has the SMS device linked (`bkash_device_id` or `nagad_device_id`),
2. `amount_poisha` is exactly equal,
3. the payment has not expired,
4. `payments.sender_number` is `NULL` or equals the SMS sender (canonical `8801XXXXXXXXX`).

The SMS row is then locked (`payment_id` set once, guarded by `WHERE payment_id IS NULL`) and the
payment is completed in the same `IMMEDIATE` transaction. If anything fails, the whole
transaction rolls back and the TrxID stays unused.

> Tip: pass `sender_number` when you know the payer's number — it makes hijacking a payment with
> the same amount impossible.

A device can only be linked to **one** app (enforced with `409 device_already_linked`); a merchant
number feeding two tenants would make settlement ambiguous.

## Deployment

```bash
npm install --omit=dev
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup
```

`ecosystem.config.js` uses `wait_ready` (PayGate calls `process.send('ready')` after listening)
and a 12s kill timeout for graceful shutdown. **Run a single instance**: SQLite and the in-process
outbox worker are not designed for horizontal scaling without moving the queue to a shared store.

Put nginx/Caddy in front for TLS and set `TRUST_PROXY=1`. The checkout page sends a strict CSP
and is safe to expose publicly; admin routes should be IP-restricted at the proxy if possible.

Back up the SQLite database with `sqlite3 data/paygate.db ".backup backup.db"` (safe while WAL is
active). Consider a cron job for off-box copies.

## Tests

```bash
npm test
```

The smoke test boots the server on a random port with a temporary database and covers device/app
registration, checkout rendering, JSON/form/query SMS ingestion, exact-amount and sender matching,
TrxID replay rejection, FIFO locking, expiry, admin endpoints and HMAC verification against a
local receiver.

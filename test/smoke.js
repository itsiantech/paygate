'use strict';

/**
 * End-to-end smoke test for PayGate.
 *
 * Boots the real server against a temporary SQLite database, registers a bKash
 * and a Nagad device, creates payments, replays SMS webhooks (JSON, form-encoded
 * and query-string), and verifies webhook signatures on a local receiver.
 *
 *   npm test
 */

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'paygate-smoke-'));

process.env.NODE_ENV = 'test';
process.env.DATABASE_PATH = path.join(tmpDir, 'paygate.db');
process.env.ADMIN_API_KEY = 'test_admin_key_123456';
process.env.WEBHOOK_ALLOW_PRIVATE_URLS = 'true';
process.env.WEBHOOK_WORKER_IDLE_MS = '100';
process.env.LOG_LEVEL = 'error';
process.env.PUBLIC_BASE_URL = 'https://pay.example.test';

const { start, stop, db } = require('../paygate.js');

const ADMIN_KEY = process.env.ADMIN_API_KEY;

let base = '';
let receiver = null;
let server = null;
const received = [];

async function api(method, route, { token, admin = false, body, rawBody, contentType } = {}) {
  const headers = { accept: 'application/json' };
  if (admin) headers['x-admin-key'] = ADMIN_KEY;
  if (token) headers.authorization = `Bearer ${token}`;

  let payload;
  if (rawBody !== undefined) {
    payload = rawBody;
    headers['content-type'] = contentType || 'application/octet-stream';
  } else if (body !== undefined) {
    payload = JSON.stringify(body);
    headers['content-type'] = 'application/json';
  }

  const response = await fetch(`${base}${route}`, { method, headers, body: payload });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: response.status, body: json, text };
}

async function waitFor(predicate, { timeout = 10000, interval = 100, label = 'condition' } = {}) {
  const started = Date.now();
  while (Date.now() - started < timeout) {
    const value = await predicate();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

function sendSms(token, payload, { form = false } = {}) {
  if (form) {
    return api('POST', `/webhook/sms/${token}`, {
      rawBody: new URLSearchParams(payload).toString(),
      contentType: 'application/x-www-form-urlencoded',
    });
  }
  return api('POST', `/webhook/sms/${token}`, { body: payload });
}

async function main() {
  receiver = http.createServer((req, res) => {
    let raw = '';
    req.on('data', (chunk) => {
      raw += chunk;
    });
    req.on('end', () => {
      received.push({ headers: req.headers, body: raw, at: Date.now() });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('{"ok":true}');
    });
  });

  await new Promise((resolve) => receiver.listen(0, '127.0.0.1', resolve));
  const receiverPort = receiver.address().port;

  server = await start(0);
  base = `http://127.0.0.1:${server.address().port}`;
  console.log(`  server     ${base}`);

  /* ---------------------------------------------------------------- devices */
  const bkash = await api('POST', '/api/admin/devices', {
    admin: true,
    body: { name: 'bKash counter', type: 'bkash', phone_number: '01711111111' },
  });
  assert.equal(bkash.status, 201, JSON.stringify(bkash.body));
  assert.equal(bkash.body.device.phone_number, '01711111111');
  assert.match(bkash.body.device.webhook_url, /\/webhook\/sms\/[a-f0-9]{48}$/);
  const bkashToken = bkash.body.device.webhook_token;

  const nagad = await api('POST', '/api/admin/devices', {
    admin: true,
    body: { name: 'Nagad counter', type: 'nagad', phone_number: '01822222222' },
  });
  assert.equal(nagad.status, 201, JSON.stringify(nagad.body));
  const nagadToken = nagad.body.device.webhook_token;

  const badDevice = await api('POST', '/api/admin/devices', {
    admin: true,
    body: { name: 'Broken', type: 'rocket', phone_number: '01711111111' },
  });
  assert.equal(badDevice.status, 400);
  assert.equal(badDevice.body.error.code, 'invalid_type');
  console.log('  devices    ok');

  /* ------------------------------------------------------------------- app */
  const appRes = await api('POST', '/api/admin/apps', {
    admin: true,
    body: {
      name: 'Shop A',
      webhook_url: `http://127.0.0.1:${receiverPort}/hooks/paygate`,
      return_url: 'https://shop.example.test/thanks',
      bkash_device_id: bkash.body.device.id,
      nagad_device_id: nagad.body.device.id,
    },
  });
  assert.equal(appRes.status, 201, JSON.stringify(appRes.body));
  const tenant = appRes.body.app;
  assert.match(tenant.pk_key, /^pk_[a-f0-9]{36}$/);
  assert.match(tenant.webhook_secret, /^whsec_[a-f0-9]{64}$/);

  const duplicateDevice = await api('POST', '/api/admin/apps', {
    admin: true,
    body: {
      name: 'Shop B',
      webhook_url: 'https://shop-b.example.test/hook',
      bkash_device_id: bkash.body.device.id,
    },
  });
  assert.equal(duplicateDevice.status, 409);
  assert.equal(duplicateDevice.body.error.code, 'device_already_linked');

  const selfRelink = await api('PATCH', `/api/admin/apps/${tenant.id}`, {
    admin: true,
    body: { bkash_device_id: bkash.body.device.id },
  });
  assert.equal(selfRelink.status, 200, JSON.stringify(selfRelink.body));
  console.log('  app        ok');

  const unauthorized = await api('POST', '/api/payments', { body: { amount: 10 } });
  assert.equal(unauthorized.status, 401);
  assert.equal(unauthorized.body.error.code, 'missing_api_key');

  /* --------------------------------------------------------------- payment */
  const created = await api('POST', '/api/payments', {
    token: tenant.pk_key,
    body: { amount: '500.50', metadata: { order_id: 'A-1001' } },
  });
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const payment = created.body.payment;
  assert.equal(payment.amount, 500.5);
  assert.equal(payment.amount_poisha, 50050);
  assert.equal(payment.status, 'pending');
  assert.equal(created.body.payment_methods.length, 2);
  assert.equal(created.body.checkout_url, `https://pay.example.test/pay/${payment.id}`);

  const checkout = await fetch(`${base}/pay/${payment.id}`);
  const checkoutHtml = await checkout.text();
  assert.equal(checkout.status, 200);
  assert.match(checkoutHtml, /bKash/);
  assert.match(checkoutHtml, /Nagad/);
  assert.match(checkoutHtml, /01711111111/);
  assert.match(checkoutHtml, /01822222222/);
  assert.match(checkoutHtml, /500\.50/);
  assert.match(checkoutHtml, /setTimeout\(poll, 4000\)/);
  // A pending page must not embed a render-time redirect URL (it would carry
  // status=pending); the client uses redirect_url from the status API instead.
  assert.match(checkoutHtml, /var redirectUrl = null;/);
  console.log('  checkout   ok');

  const wrongAmount = await sendSms(bkashToken, {
    message: 'You have received Tk 499.00 from 01712345678. TrxID WRONGAMT01. Balance Tk 100.00.',
  });
  assert.equal(wrongAmount.status, 200);
  assert.equal(wrongAmount.body.matched, false);

  /* ---------------------------------------------------- successful matching */
  const sms = await sendSms(bkashToken, {
    message:
      'You have received Tk 500.50 from 01712345678. TrxID ABC1234567. Your new balance is Tk 1200.00.',
  });
  assert.equal(sms.status, 200, JSON.stringify(sms.body));
  assert.equal(sms.body.matched, true);
  assert.equal(sms.body.payment_id, payment.id);

  const statusRes = await api('GET', `/api/public/payments/${payment.id}`);
  assert.equal(statusRes.status, 200);
  assert.equal(statusRes.body.status, 'success');
  assert.equal(statusRes.body.trx_id, 'ABC1234567');
  assert.equal(
    statusRes.body.redirect_url,
    `https://shop.example.test/thanks?payment_id=${payment.id}&status=success&trx_id=ABC1234567`
  );

  const replay = await sendSms(bkashToken, {
    message:
      'You have received Tk 500.50 from 01712345678. TrxID ABC1234567. Your new balance is Tk 1200.00.',
  });
  assert.equal(replay.body.duplicate, true);

  const reusedTrx = await sendSms(bkashToken, {
    message: 'You have received Tk 500.50 from 01799999999. TrxID ABC1234567. Balance Tk 1.00.',
  });
  assert.equal(reusedTrx.body.duplicate, true);
  assert.equal(reusedTrx.body.reason, 'trx_id_already_recorded');
  console.log('  matching   ok');

  /* ------------------------------------------------------- webhook signing */
  const event = await waitFor(
    () =>
      received.find((item) => {
        try {
          const parsed = JSON.parse(item.body);
          return parsed.type === 'payment.succeeded' && parsed.data.id === payment.id;
        } catch {
          return false;
        }
      }),
    { label: 'signed payment.succeeded webhook' }
  );

  const timestamp = event.headers['x-paygate-timestamp'];
  const expectedSignature = crypto
    .createHmac('sha256', tenant.webhook_secret)
    .update(`${timestamp}.${event.body}`)
    .digest('hex');
  assert.equal(event.headers['x-paygate-signature'], `sha256=${expectedSignature}`);
  assert.equal(event.headers['x-paygate-event'], 'payment.succeeded');
  assert.match(timestamp, /^\d{10}$/);

  const payload = JSON.parse(event.body);
  assert.equal(payload.object, 'event');
  assert.equal(payload.data.trx_id, 'ABC1234567');
  assert.equal(payload.data.amount_poisha, 50050);
  assert.equal(payload.data.sender_number, '01712345678');
  console.log('  webhook    ok (HMAC verified)');

  /* --------------------------------------------------- TrxID lock / FIFO */
  const first = await api('POST', '/api/payments', { token: tenant.pk_key, body: { amount: 700 } });
  const second = await api('POST', '/api/payments', { token: tenant.pk_key, body: { amount: 700 } });
  assert.equal(first.status, 201);
  assert.equal(second.status, 201);

  const fifo = await sendSms(bkashToken, {
    message: 'You have received Tk 700.00 from 01712345678. TrxID FIFO000001. Balance Tk 5000.00.',
  });
  assert.equal(fifo.body.matched, true);
  assert.equal(fifo.body.payment_id, first.body.payment.id);

  const secondStillPending = await api('GET', `/api/payments/${second.body.payment.id}`, {
    token: tenant.pk_key,
  });
  assert.equal(secondStillPending.body.payment.status, 'pending');

  const hijack = await sendSms(bkashToken, {
    message: 'You have received Tk 700.00 from 01712345678. TrxID FIFO000001. Balance Tk 4300.00.',
  });
  assert.equal(hijack.body.duplicate, true);
  console.log('  trx lock   ok');

  /* ------------------------------------------- sender-number constrained */
  const pinned = await api('POST', '/api/payments', {
    token: tenant.pk_key,
    body: { amount: 300, sender_number: '01911111111' },
  });
  assert.equal(pinned.status, 201, JSON.stringify(pinned.body));

  const wrongSender = await sendSms(bkashToken, {
    message: 'You have received Tk 300.00 from 01799999999. TrxID SENDER0001. Balance Tk 1.00.',
  });
  assert.equal(wrongSender.body.matched, false);
  assert.equal(wrongSender.body.reason, 'no_matching_payment');

  const rightSender = await sendSms(bkashToken, {
    message: 'You have received Tk 300.00 from 01911111111. TrxID SENDER0002. Balance Tk 1.00.',
  });
  assert.equal(rightSender.body.matched, true);
  assert.equal(rightSender.body.payment_id, pinned.body.payment.id);
  console.log('  sender pin ok');

  /* -------------------------------------------------- form-encoded Nagad */
  const nagadPayment = await api('POST', '/api/payments', {
    token: tenant.pk_key,
    body: { amount: 150 },
  });
  const nagadSms = await sendSms(
    nagadToken,
    {
      message:
        'You have received Tk 150.00 from 01833333333. TrxID NAGAD98765. Balance Tk 1000.00.',
    },
    { form: true }
  );
  assert.equal(nagadSms.body.matched, true, JSON.stringify(nagadSms.body));
  assert.equal(nagadSms.body.payment_id, nagadPayment.body.payment.id);

  const queryPayment = await api('POST', '/api/payments', {
    token: tenant.pk_key,
    body: { amount: 222 },
  });
  const querySms = await api(
    'GET',
    `/webhook/sms/${bkashToken}?message=${encodeURIComponent(
      'You have received Tk 222.00 from 01744444444. TrxID QUERY00001. Balance Tk 10.00.'
    )}`
  );
  assert.equal(querySms.status, 200, JSON.stringify(querySms.body));
  assert.equal(querySms.body.matched, true);
  assert.equal(querySms.body.payment_id, queryPayment.body.payment.id);
  console.log('  encodings  ok');

  /* -------------------------------------------------------------- expiry */
  const expiring = await api('POST', '/api/payments', {
    token: tenant.pk_key,
    body: { amount: 111 },
  });
  db.prepare('UPDATE payments SET expires_at = ? WHERE id = ?').run(Date.now() - 1000, expiring.body.payment.id);
  const expiredStatus = await api('GET', `/api/public/payments/${expiring.body.payment.id}`);
  assert.equal(expiredStatus.body.status, 'expired');

  const expiredEvent = db
    .prepare("SELECT * FROM webhook_outbox WHERE payment_id = ? AND event = 'payment.expired'")
    .get(expiring.body.payment.id);
  assert.ok(expiredEvent, 'payment.expired event should be enqueued');
  console.log('  expiry     ok');

  /* ---------------------------------------------------------------- admin */
  const stats = await api('GET', '/api/admin/stats', { admin: true });
  assert.equal(stats.status, 200);
  assert.equal(stats.body.devices, 2);
  assert.equal(stats.body.apps, 1);
  assert.ok(stats.body.payments.success >= 4);

  const smsList = await api('GET', '/api/admin/sms?status=unmatched', { admin: true });
  assert.equal(smsList.status, 200);
  assert.ok(smsList.body.data.some((row) => row.trx_id === 'WRONGAMT01'));

  const garbage = await sendSms(bkashToken, { message: 'Hello world, no payment here.' });
  assert.equal(garbage.status, 422);
  assert.equal(garbage.body.error, 'unparseable_sms');

  const smsEvents = await api('GET', '/api/admin/sms/events?status=unparseable', { admin: true });
  assert.equal(smsEvents.status, 200);
  assert.ok(smsEvents.body.data.length >= 1);

  const outboxList = await api('GET', '/api/admin/outbox?status=delivered', { admin: true });
  assert.equal(outboxList.status, 200);
  assert.ok(outboxList.body.data.length >= 1);

  const wrongAdmin = await fetch(`${base}/api/admin/stats`, { headers: { 'x-admin-key': 'nope' } });
  assert.equal(wrongAdmin.status, 401);

  const notFound = await api('GET', '/pay/pay_doesnotexist');
  assert.equal(notFound.status, 404);
  console.log('  admin      ok');

  console.log('\nAll smoke tests passed.');
}

main()
  .then(async () => {
    await stop();
    await new Promise((resolve) => (receiver ? receiver.close(resolve) : resolve()));
    fs.rmSync(tmpDir, { recursive: true, force: true });
    process.exit(0);
  })
  .catch(async (err) => {
    console.error('\nSMOKE TEST FAILED');
    console.error(err && err.stack ? err.stack : err);
    try {
      await stop();
    } catch {
      /* ignore */
    }
    try {
      await new Promise((resolve) => (receiver ? receiver.close(resolve) : resolve()));
    } catch {
      /* ignore */
    }
    console.error(`Temp database kept at ${tmpDir}`);
    process.exit(1);
  });

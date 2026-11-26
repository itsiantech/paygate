#!/usr/bin/env node
'use strict';

/**
 * PayGate — multi-tenant SMS payment verification gateway for bKash & Nagad.
 *
 * Flow:
 *   1. Admin registers a device (bKash/Nagad) -> gets a webhook token.
 *   2. Admin registers an app (SaaS tenant) -> gets pk_ API key + whsec_ secret,
 *      and links one bKash device and/or one Nagad device.
 *   3. App creates a payment intent (POST /api/payments) -> hosted checkout URL.
 *   4. Customer sends the exact amount to the displayed merchant number.
 *   5. The SMS forwarder on the device POSTs the SMS to /webhook/sms/:token.
 *   6. PayGate parses amount / sender / TrxID, atomically locks the TrxID to the
 *      single matching pending payment (exact amount + sender), and enqueues a
 *      signed webhook in the outbox.
 *   7. The outbox worker delivers `payment.succeeded` with HMAC-SHA256 retries.
 *
 * Requires Node.js >= 20.
 */

const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const express = require('express');
const Database = require('better-sqlite3');

const VERSION = '1.0.0';

/* -------------------------------------------------------------------------- *
 * Environment
 * -------------------------------------------------------------------------- */

/**
 * Minimal .env loader (no dependency). Existing process.env values win.
 */
function loadEnvFile(file) {
  if (!fs.existsSync(file)) return;
  const source = fs.readFileSync(file, 'utf8');
  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const eq = line.indexOf('=');
    if (eq < 1) continue;
    let key = line.slice(0, eq).trim();
    if (key.startsWith('export ')) key = key.slice(7).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    if (Object.prototype.hasOwnProperty.call(process.env, key)) continue;
    let value = line.slice(eq + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      value = value.slice(1, -1);
      if (value.includes('\\n')) value = value.replace(/\\n/g, '\n');
    } else {
      const comment = value.indexOf(' #');
      if (comment >= 0) value = value.slice(0, comment).trim();
    }
    process.env[key] = value;
  }
}

loadEnvFile(path.join(__dirname, '.env'));

function envStr(name, fallback = '') {
  const value = process.env[name];
  return value === undefined || value === '' ? fallback : String(value);
}

function envInt(name, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function envBool(name, fallback = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return fallback;
  return /^(1|true|yes|on)$/i.test(raw.trim());
}

function parseTrustProxy(value) {
  if (!value) return false;
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

const NODE_ENV = envStr('NODE_ENV', 'development');

let adminKey = envStr('ADMIN_API_KEY');
let adminKeyGenerated = false;
if (!adminKey) {
  if (NODE_ENV === 'production') {
    // eslint-disable-next-line no-console
    console.error('[paygate] FATAL: ADMIN_API_KEY must be set in production.');
    process.exit(1);
  }
  adminKey = `dev_${crypto.randomBytes(18).toString('hex')}`;
  adminKeyGenerated = true;
}

const config = Object.freeze({
  env: NODE_ENV,
  host: envStr('HOST', '0.0.0.0'),
  port: envInt('PORT', 3000, { min: 0, max: 65535 }),
  dbPath: path.resolve(__dirname, envStr('DATABASE_PATH', './data/paygate.db')),
  publicBaseUrl: envStr('PUBLIC_BASE_URL').replace(/\/+$/, ''),
  adminKey,
  adminKeyGenerated,
  trustProxy: parseTrustProxy(envStr('TRUST_PROXY')),
  paymentTtlSeconds: envInt('PAYMENT_TTL_SECONDS', 900, { min: 60, max: 604800 }),
  maxPaymentPoisha: envInt('MAX_PAYMENT_AMOUNT_BDT', 500000, { min: 1, max: 10000000 }) * 100,
  logLevel: envStr('LOG_LEVEL', 'info').toLowerCase(),
  webhook: Object.freeze({
    timeoutMs: envInt('WEBHOOK_TIMEOUT_MS', 10000, { min: 1000, max: 60000 }),
    maxAttempts: envInt('WEBHOOK_MAX_ATTEMPTS', 10, { min: 1, max: 50 }),
    batchSize: envInt('WEBHOOK_BATCH_SIZE', 20, { min: 1, max: 200 }),
    concurrency: envInt('WEBHOOK_CONCURRENCY', 5, { min: 1, max: 50 }),
    idleMs: envInt('WEBHOOK_WORKER_IDLE_MS', 1000, { min: 100, max: 60000 }),
    retentionDays: envInt('WEBHOOK_RETENTION_DAYS', 30, { min: 1, max: 365 }),
    allowPrivateUrls: envBool('WEBHOOK_ALLOW_PRIVATE_URLS', NODE_ENV !== 'production'),
  }),
  smsRetentionDays: envInt('SMS_RETENTION_DAYS', 30, { min: 1, max: 365 }),
  rateLimit: Object.freeze({
    windowMs: 60_000,
    publicMax: envInt('RATE_LIMIT_PUBLIC_PER_MIN', 240, { min: 10, max: 100000 }),
    webhookMax: envInt('RATE_LIMIT_WEBHOOK_PER_MIN', 600, { min: 10, max: 100000 }),
  }),
});

/* -------------------------------------------------------------------------- *
 * Logging
 * -------------------------------------------------------------------------- */

const LOG_LEVELS = { debug: 10, info: 20, warn: 30, error: 40, silent: 100 };
const LOG_LEVEL = LOG_LEVELS[config.logLevel] === undefined ? LOG_LEVELS.info : LOG_LEVELS[config.logLevel];

function log(level, message, meta) {
  if (LOG_LEVELS[level] < LOG_LEVEL) return;
  const line = `${new Date().toISOString()} ${level.toUpperCase().padEnd(5)} ${message}`;
  const output = meta && Object.keys(meta).length ? `${line} ${JSON.stringify(meta)}` : line;
  if (level === 'error') console.error(output);
  else if (level === 'warn') console.warn(output);
  else console.log(output);
}

/* -------------------------------------------------------------------------- *
 * Small helpers
 * -------------------------------------------------------------------------- */

const BDT = '\u09F3'; // ৳

function nowMs() {
  return Date.now();
}

function iso(ms) {
  return ms === null || ms === undefined ? null : new Date(ms).toISOString();
}

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function timingSafeEqualStr(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function safeJson(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function escapeHtml(value) {
  return String(value === null || value === undefined ? '' : value).replace(/[&<>"']/g, (ch) => {
    switch (ch) {
      case '&': return '&amp;';
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '"': return '&quot;';
      default: return '&#39;';
    }
  });
}

/** Safely embed a value into an inline <script> block. */
function jsString(value) {
  return JSON.stringify(value === undefined ? null : value)
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function clampInt(value, min, max, fallback) {
  const n = Number.parseInt(value, 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}

function cleanString(value, min = 1, max = 255) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (trimmed.length < min || trimmed.length > max) return null;
  return trimmed;
}

/** Accept booleans, 0/1 and common string spellings; otherwise keep the fallback. */
function parseActive(value, fallback) {
  if (value === undefined) return fallback;
  if (typeof value === 'boolean') return value ? 1 : 0;
  if (value === 1 || value === 0) return value;
  if (typeof value === 'string') {
    if (/^(1|true|yes|on)$/i.test(value.trim())) return 1;
    if (/^(0|false|no|off)$/i.test(value.trim())) return 0;
  }
  return fallback;
}

/**
 * Parse a BDT amount (number or string) into integer poisha.
 * Returns null for anything that is not a positive amount with <= 2 decimals.
 */
function parseMoneyToPoisha(input) {
  if (input === null || input === undefined || input === '') return null;
  let text = typeof input === 'number' ? String(input) : String(input).trim();
  text = text.replace(/,/g, '').replace(/^(?:tk\.?|bdt|\u09F3)\s*/i, '').trim();
  if (!/^\d{1,12}(?:\.\d{1,2})?$/.test(text)) return null;
  const [whole, fraction = ''] = text.split('.');
  const poisha = Number(whole) * 100 + Number(`${fraction}00`.slice(0, 2));
  if (!Number.isSafeInteger(poisha) || poisha <= 0) return null;
  return poisha;
}

function formatAmount(poisha) {
  return (poisha / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

/**
 * Normalise a Bangladeshi mobile number to 8801XXXXXXXXX form.
 * Returns null when the number is not a valid BD mobile number.
 */
function normalizePhone(input) {
  if (input === null || input === undefined) return null;
  let digits = String(input).replace(/[^\d]/g, '');
  if (digits.startsWith('00880')) digits = digits.slice(2);
  if (digits.length === 10 && digits.startsWith('1')) digits = `880${digits}`;
  else if (digits.length === 11 && digits.startsWith('0')) digits = `88${digits}`;
  if (!/^8801[3-9]\d{8}$/.test(digits)) return null;
  return digits;
}

function displayPhone(canonical) {
  if (!canonical) return null;
  return canonical.startsWith('880') ? `0${canonical.slice(3)}` : canonical;
}

/** Accept only absolute http(s) URLs. */
function normalizeHttpUrl(input, { maxLength = 2048 } = {}) {
  if (typeof input !== 'string') return null;
  const trimmed = input.trim();
  if (!trimmed || trimmed.length > maxLength) return null;
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  if (url.username || url.password) return null;
  if (!url.hostname) return null;
  return url.toString();
}

const PRIVATE_IPV4_PATTERN = /^(0\.|10\.|127\.|169\.254\.|192\.168\.)/;

/**
 * Best-effort SSRF guard for webhook targets. Only literal hosts are checked
 * here; DNS rebinding cannot be fully prevented without pinning resolved IPs.
 */
function isPrivateHost(hostname) {
  const host = String(hostname || '').toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;

  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    if (PRIVATE_IPV4_PATTERN.test(host)) return true;
    return /^172\.(?:1[6-9]|2\d|3[01])\./.test(host);
  }

  if (host.includes(':')) {
    // IPv6 literal
    if (host === '::1' || host === '::') return true;
    if (host.startsWith('::ffff:')) return true;
    return /^(?:fc|fd|fe80)/.test(host);
  }

  return false;
}

function buildReturnUrl(returnUrl, payment) {
  if (!returnUrl) return null;
  try {
    const url = new URL(returnUrl);
    url.searchParams.set('payment_id', payment.id);
    url.searchParams.set('status', payment.status);
    if (payment.trx_id) url.searchParams.set('trx_id', payment.trx_id);
    return url.toString();
  } catch {
    return null;
  }
}

/* -------------------------------------------------------------------------- *
 * Database
 * -------------------------------------------------------------------------- */

fs.mkdirSync(path.dirname(config.dbPath), { recursive: true });

const db = new Database(config.dbPath);
db.pragma('journal_mode = WAL');
db.pragma('synchronous = NORMAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 5000');

db.exec(`
CREATE TABLE IF NOT EXISTS devices (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT    NOT NULL,
  type          TEXT    NOT NULL CHECK (type IN ('bkash', 'nagad')),
  phone_number  TEXT,
  webhook_token TEXT    NOT NULL UNIQUE,
  active        INTEGER NOT NULL DEFAULT 1,
  last_seen_at  INTEGER,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS apps (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  name            TEXT    NOT NULL,
  pk_key          TEXT    NOT NULL UNIQUE,
  whsec           TEXT    NOT NULL,
  webhook_url     TEXT,
  return_url      TEXT,
  bkash_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
  nagad_device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
  active          INTEGER NOT NULL DEFAULT 1,
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS payments (
  id            TEXT    PRIMARY KEY,
  app_id        INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  amount_poisha INTEGER NOT NULL CHECK (amount_poisha > 0),
  currency      TEXT    NOT NULL DEFAULT 'BDT',
  status        TEXT    NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'success', 'expired', 'cancelled')),
  sender_number TEXT,
  trx_id        TEXT,
  device_id     INTEGER REFERENCES devices(id) ON DELETE SET NULL,
  return_url    TEXT,
  metadata      TEXT,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  paid_at       INTEGER,
  updated_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payments_app_created ON payments (app_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_payments_match ON payments (status, amount_poisha, expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_payments_trx ON payments (trx_id) WHERE trx_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS sms_payments (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id     INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  trx_id        TEXT    NOT NULL UNIQUE,
  amount_poisha INTEGER NOT NULL,
  sender_number TEXT    NOT NULL,
  raw_sms       TEXT    NOT NULL,
  payment_id    TEXT    REFERENCES payments(id) ON DELETE SET NULL,
  locked_at     INTEGER,
  received_at   INTEGER NOT NULL,
  created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sms_unmatched ON sms_payments (payment_id, amount_poisha, received_at);

CREATE TABLE IF NOT EXISTS sms_events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  raw_hash   TEXT    NOT NULL,
  raw_body   TEXT    NOT NULL,
  status     TEXT    NOT NULL,
  error      TEXT,
  trx_id     TEXT,
  payment_id TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE (device_id, raw_hash)
);
CREATE INDEX IF NOT EXISTS idx_sms_events_created ON sms_events (created_at DESC);

CREATE TABLE IF NOT EXISTS webhook_outbox (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id         TEXT    NOT NULL UNIQUE,
  app_id           INTEGER NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
  payment_id       TEXT    REFERENCES payments(id) ON DELETE CASCADE,
  event            TEXT    NOT NULL,
  payload          TEXT    NOT NULL,
  status           TEXT    NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending', 'delivering', 'delivered', 'failed')),
  attempts         INTEGER NOT NULL DEFAULT 0,
  next_attempt_at  INTEGER NOT NULL,
  locked_until     INTEGER,
  last_status_code INTEGER,
  last_error       TEXT,
  delivered_at     INTEGER,
  created_at       INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_unique_event
  ON webhook_outbox (payment_id, event) WHERE payment_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_outbox_due ON webhook_outbox (status, next_attempt_at);
`);

/* -------------------------------------------------------------------------- *
 * Prepared statements
 * -------------------------------------------------------------------------- */

const stmt = {
  deviceById: db.prepare('SELECT * FROM devices WHERE id = ?'),
  deviceByToken: db.prepare('SELECT * FROM devices WHERE webhook_token = ?'),
  devicesAll: db.prepare('SELECT * FROM devices ORDER BY id DESC'),
  insertDevice: db.prepare(
    'INSERT INTO devices (name, type, phone_number, webhook_token, active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)'
  ),
  updateDevice: db.prepare(
    'UPDATE devices SET name = ?, phone_number = ?, active = ?, webhook_token = ?, updated_at = ? WHERE id = ?'
  ),
  touchDevice: db.prepare('UPDATE devices SET last_seen_at = ?, updated_at = ? WHERE id = ?'),
  deleteDevice: db.prepare('DELETE FROM devices WHERE id = ?'),

  appById: db.prepare('SELECT * FROM apps WHERE id = ?'),
  appByKey: db.prepare('SELECT * FROM apps WHERE pk_key = ?'),
  appsAll: db.prepare('SELECT * FROM apps ORDER BY id DESC'),
  insertApp: db.prepare(
    `INSERT INTO apps (name, pk_key, whsec, webhook_url, return_url, bkash_device_id, nagad_device_id, active, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
  ),
  updateApp: db.prepare(
    `UPDATE apps SET name = ?, pk_key = ?, whsec = ?, webhook_url = ?, return_url = ?,
       bkash_device_id = ?, nagad_device_id = ?, active = ?, updated_at = ? WHERE id = ?`
  ),
  deleteApp: db.prepare('DELETE FROM apps WHERE id = ?'),
  appsUsingDevice: db.prepare('SELECT id, name FROM apps WHERE bkash_device_id = ? OR nagad_device_id = ?'),
  appUsingDeviceExcept: db.prepare(
    'SELECT id, name FROM apps WHERE (bkash_device_id = ? OR nagad_device_id = ?) AND id != ? LIMIT 1'
  ),

  paymentById: db.prepare('SELECT * FROM payments WHERE id = ?'),
  insertPayment: db.prepare(
    `INSERT INTO payments
      (id, app_id, amount_poisha, currency, status, sender_number, return_url, metadata, created_at, expires_at, updated_at)
     VALUES (?, ?, ?, 'BDT', 'pending', ?, ?, ?, ?, ?, ?)`
  ),
  paymentsByApp: db.prepare(
    'SELECT * FROM payments WHERE app_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ),
  paymentsByAppStatus: db.prepare(
    'SELECT * FROM payments WHERE app_id = ? AND status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ),
  paymentsAll: db.prepare('SELECT * FROM payments ORDER BY created_at DESC LIMIT ? OFFSET ?'),
  paymentsAllStatus: db.prepare(
    'SELECT * FROM payments WHERE status = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ),
  paymentsToExpire: db.prepare("SELECT id FROM payments WHERE status = 'pending' AND expires_at <= ?"),
  expirePayment: db.prepare(
    "UPDATE payments SET status = 'expired', updated_at = ? WHERE id = ? AND status = 'pending'"
  ),
  cancelPayment: db.prepare(
    "UPDATE payments SET status = 'cancelled', updated_at = ? WHERE id = ? AND status = 'pending'"
  ),
  completePayment: db.prepare(
    `UPDATE payments
       SET status = 'success', trx_id = ?, sender_number = ?, device_id = ?, paid_at = ?, updated_at = ?
     WHERE id = ? AND status = 'pending'`
  ),
  matchPayment: db.prepare(
    `SELECT p.*
       FROM payments p
       JOIN apps a ON a.id = p.app_id
      WHERE p.status = 'pending'
        AND p.amount_poisha = ?
        AND p.expires_at > ?
        AND a.active = 1
        AND (a.bkash_device_id = ? OR a.nagad_device_id = ?)
        AND (p.sender_number IS NULL OR p.sender_number = ?)
      ORDER BY p.created_at ASC, p.rowid ASC
      LIMIT 1`
  ),

  insertSmsPayment: db.prepare(
    `INSERT OR IGNORE INTO sms_payments
      (device_id, trx_id, amount_poisha, sender_number, raw_sms, received_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ),
  smsPaymentById: db.prepare('SELECT * FROM sms_payments WHERE id = ?'),
  smsPaymentByTrx: db.prepare('SELECT * FROM sms_payments WHERE trx_id = ?'),
  lockSmsPayment: db.prepare(
    'UPDATE sms_payments SET payment_id = ?, locked_at = ? WHERE id = ? AND payment_id IS NULL'
  ),
  smsUnmatched: db.prepare(
    `SELECT s.*, d.name AS device_name, d.type AS device_type
       FROM sms_payments s JOIN devices d ON d.id = s.device_id
      WHERE s.payment_id IS NULL ORDER BY s.id DESC LIMIT ?`
  ),
  smsAll: db.prepare(
    `SELECT s.*, d.name AS device_name, d.type AS device_type
       FROM sms_payments s JOIN devices d ON d.id = s.device_id
      ORDER BY s.id DESC LIMIT ?`
  ),
  smsEventsAll: db.prepare('SELECT * FROM sms_events ORDER BY id DESC LIMIT ?'),
  smsEventsByStatus: db.prepare('SELECT * FROM sms_events WHERE status = ? ORDER BY id DESC LIMIT ?'),

  insertSmsEvent: db.prepare(
    'INSERT OR IGNORE INTO sms_events (device_id, raw_hash, raw_body, status, created_at) VALUES (?, ?, ?, ?, ?)'
  ),
  updateSmsEvent: db.prepare('UPDATE sms_events SET status = ?, error = ?, trx_id = ?, payment_id = ? WHERE id = ?'),

  insertOutbox: db.prepare(
    `INSERT OR IGNORE INTO webhook_outbox
      (event_id, app_id, payment_id, event, payload, status, attempts, next_attempt_at, created_at)
     VALUES (?, ?, ?, ?, ?, 'pending', 0, ?, ?)`
  ),
  outboxDue: db.prepare(
    `SELECT o.*, a.whsec AS app_whsec, a.webhook_url AS app_webhook_url, a.active AS app_active
       FROM webhook_outbox o JOIN apps a ON a.id = o.app_id
      WHERE o.status = 'pending' AND o.next_attempt_at <= ?
      ORDER BY o.next_attempt_at ASC, o.id ASC
      LIMIT ?`
  ),
  claimOutbox: db.prepare(
    "UPDATE webhook_outbox SET status = 'delivering', locked_until = ? WHERE id = ? AND status = 'pending'"
  ),
  outboxDelivered: db.prepare(
    `UPDATE webhook_outbox
       SET status = 'delivered', attempts = ?, last_status_code = ?, last_error = NULL,
           delivered_at = ?, locked_until = NULL
     WHERE id = ?`
  ),
  outboxRetry: db.prepare(
    `UPDATE webhook_outbox
       SET status = 'pending', attempts = ?, last_status_code = ?, last_error = ?,
           next_attempt_at = ?, locked_until = NULL
     WHERE id = ?`
  ),
  outboxFailed: db.prepare(
    `UPDATE webhook_outbox
       SET status = 'failed', attempts = ?, last_status_code = ?, last_error = ?, locked_until = NULL
     WHERE id = ?`
  ),
  outboxResetStale: db.prepare(
    "UPDATE webhook_outbox SET status = 'pending', locked_until = NULL WHERE status = 'delivering' AND (locked_until IS NULL OR locked_until < ?)"
  ),
  outboxById: db.prepare('SELECT * FROM webhook_outbox WHERE id = ?'),
  outboxRetryManual: db.prepare(
    "UPDATE webhook_outbox SET status = 'pending', next_attempt_at = ?, locked_until = NULL WHERE id = ? AND status IN ('failed', 'delivered')"
  ),
  outboxAll: db.prepare(
    `SELECT o.id, o.event_id, o.app_id, o.payment_id, o.event, o.status, o.attempts,
            o.next_attempt_at, o.last_status_code, o.last_error, o.delivered_at, o.created_at,
            a.name AS app_name
       FROM webhook_outbox o JOIN apps a ON a.id = o.app_id
      ORDER BY o.id DESC LIMIT ?`
  ),
  outboxAllStatus: db.prepare(
    `SELECT o.id, o.event_id, o.app_id, o.payment_id, o.event, o.status, o.attempts,
            o.next_attempt_at, o.last_status_code, o.last_error, o.delivered_at, o.created_at,
            a.name AS app_name
       FROM webhook_outbox o JOIN apps a ON a.id = o.app_id
      WHERE o.status = ? ORDER BY o.id DESC LIMIT ?`
  ),

  pruneSmsEvents: db.prepare('DELETE FROM sms_events WHERE created_at < ?'),
  pruneOutbox: db.prepare(
    "DELETE FROM webhook_outbox WHERE status IN ('delivered', 'failed') AND created_at < ?"
  ),
  pruneUnmatchedSms: db.prepare('DELETE FROM sms_payments WHERE payment_id IS NULL AND created_at < ?'),
};

/* -------------------------------------------------------------------------- *
 * Serialisers
 * -------------------------------------------------------------------------- */

function baseUrl(req) {
  if (config.publicBaseUrl) return config.publicBaseUrl;
  return `${req.protocol}://${req.get('host')}`;
}

function serializeDevice(device, base) {
  return {
    id: device.id,
    object: 'device',
    name: device.name,
    type: device.type,
    phone_number: displayPhone(device.phone_number),
    webhook_token: device.webhook_token,
    webhook_url: `${base}/webhook/sms/${device.webhook_token}`,
    active: Boolean(device.active),
    last_seen_at: iso(device.last_seen_at),
    created_at: iso(device.created_at),
    updated_at: iso(device.updated_at),
  };
}

function serializeApp(app) {
  return {
    id: app.id,
    object: 'app',
    name: app.name,
    pk_key: app.pk_key,
    webhook_secret: app.whsec,
    webhook_url: app.webhook_url,
    return_url: app.return_url,
    bkash_device_id: app.bkash_device_id,
    nagad_device_id: app.nagad_device_id,
    active: Boolean(app.active),
    created_at: iso(app.created_at),
    updated_at: iso(app.updated_at),
  };
}

function serializePayment(payment, base = config.publicBaseUrl) {
  return {
    id: payment.id,
    object: 'payment',
    app_id: payment.app_id,
    amount: payment.amount_poisha / 100,
    amount_poisha: payment.amount_poisha,
    currency: payment.currency,
    status: payment.status,
    trx_id: payment.trx_id || null,
    sender_number: payment.sender_number ? displayPhone(payment.sender_number) : null,
    device_id: payment.device_id || null,
    return_url: payment.return_url || null,
    checkout_url: base ? `${base}/pay/${payment.id}` : null,
    metadata: safeJson(payment.metadata),
    created_at: iso(payment.created_at),
    expires_at: iso(payment.expires_at),
    paid_at: iso(payment.paid_at),
  };
}

function serializePublicPayment(payment) {
  return {
    id: payment.id,
    object: 'payment',
    amount: payment.amount_poisha / 100,
    currency: payment.currency,
    status: payment.status,
    trx_id: payment.trx_id || null,
    created_at: iso(payment.created_at),
    expires_at: iso(payment.expires_at),
    paid_at: iso(payment.paid_at),
  };
}

function fail(res, status, code, message, details) {
  const body = { error: { code, message } };
  if (details !== undefined) body.error.details = details;
  return res.status(status).json(body);
}

/* -------------------------------------------------------------------------- *
 * Webhook outbox
 * -------------------------------------------------------------------------- */

const RETRY_DELAYS_MS = [
  10_000, 30_000, 60_000, 300_000, 900_000, 1_800_000, 3_600_000, 7_200_000, 21_600_000, 43_200_000,
];

/**
 * Build the signed event payload for a payment and enqueue it (idempotently).
 * Must be called inside the same transaction as the state change it describes.
 */
function enqueuePaymentEvent(paymentId, event) {
  const row = db
    .prepare(
      `SELECT p.*, a.webhook_url, a.active AS app_active, d.type AS device_type
         FROM payments p
         JOIN apps a ON a.id = p.app_id
    LEFT JOIN devices d ON d.id = p.device_id
        WHERE p.id = ?`
    )
    .get(paymentId);

  if (!row || !row.webhook_url) return null;

  const eventId = `evt_${randomHex(12)}`;
  const body = JSON.stringify({
    id: eventId,
    object: 'event',
    type: event,
    created_at: iso(nowMs()),
    data: {
      id: row.id,
      object: 'payment',
      amount: row.amount_poisha / 100,
      amount_poisha: row.amount_poisha,
      currency: row.currency,
      status: row.status,
      trx_id: row.trx_id || null,
      sender_number: row.sender_number ? displayPhone(row.sender_number) : null,
      device_type: row.device_type || null,
      metadata: safeJson(row.metadata),
      created_at: iso(row.created_at),
      paid_at: iso(row.paid_at),
      checkout_url: config.publicBaseUrl ? `${config.publicBaseUrl}/pay/${row.id}` : null,
    },
  });

  const inserted = stmt.insertOutbox.run(eventId, row.app_id, row.id, event, body, nowMs(), nowMs());
  return inserted.changes === 1 ? eventId : null;
}

/**
 * Atomically match an SMS payment row to the oldest eligible pending payment.
 * Locks the TrxID exactly once; exact amount + sender number are required.
 */
const settleSms = db.transaction((smsId) => {
  const sms = stmt.smsPaymentById.get(smsId);
  if (!sms) return { status: 'not_found' };
  if (sms.payment_id) return { status: 'already_matched', payment_id: sms.payment_id };

  const payment = stmt.matchPayment.get(
    sms.amount_poisha,
    nowMs(),
    sms.device_id,
    sms.device_id,
    sms.sender_number
  );
  if (!payment) return { status: 'unmatched' };

  const lock = stmt.lockSmsPayment.run(payment.id, nowMs(), sms.id);
  if (lock.changes !== 1) return { status: 'already_matched', payment_id: payment.id };

  const completed = stmt.completePayment.run(
    sms.trx_id,
    sms.sender_number,
    sms.device_id,
    nowMs(),
    nowMs(),
    payment.id
  );
  if (completed.changes !== 1) {
    // Throwing rolls the whole transaction back, releasing the SMS lock.
    throw new Error(`payment ${payment.id} changed state during settlement`);
  }

  enqueuePaymentEvent(payment.id, 'payment.succeeded');
  return { status: 'matched', payment_id: payment.id };
});

const expirePaymentTx = db.transaction((paymentId) => {
  const changed = stmt.expirePayment.run(nowMs(), paymentId);
  if (changed.changes === 1) enqueuePaymentEvent(paymentId, 'payment.expired');
  return changed.changes === 1;
});

function expireIfNeeded(payment) {
  if (payment && payment.status === 'pending' && payment.expires_at <= nowMs()) {
    if (expirePaymentTx.immediate(payment.id)) return { ...payment, status: 'expired' };
  }
  return payment;
}

async function drainOnce(res) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < 4096) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value));
      total += value.length;
    }
  } catch {
    /* ignore body read errors */
  } finally {
    try {
      await reader.cancel();
    } catch {
      /* ignore */
    }
  }
  return Buffer.concat(chunks).toString('utf8').slice(0, 4096);
}

async function deliverOutboxRow(row) {
  const now = nowMs();

  if (!row.app_webhook_url) {
    stmt.outboxFailed.run(row.attempts + 1, null, 'app has no webhook_url', row.id);
    log('warn', 'webhook dropped: app has no webhook_url', { outbox_id: row.id, app_id: row.app_id });
    return;
  }

  let target;
  try {
    target = new URL(row.app_webhook_url);
    if (target.protocol !== 'https:' && target.protocol !== 'http:') throw new Error('unsupported protocol');
    if (!config.webhook.allowPrivateUrls && isPrivateHost(target.hostname)) {
      throw new Error('private network webhook targets are disabled');
    }
  } catch (err) {
    stmt.outboxFailed.run(row.attempts + 1, null, `invalid webhook_url: ${err.message}`, row.id);
    log('warn', 'webhook dropped: invalid webhook_url', { outbox_id: row.id, error: err.message });
    return;
  }

  if (!row.app_active) {
    // The tenant is disabled: keep retrying until max attempts so re-enabling
    // the app does not lose events.
    scheduleRetry(row, null, 'app is inactive', now);
    return;
  }

  const timestamp = Math.floor(now / 1000).toString();
  const signature = crypto
    .createHmac('sha256', row.app_whsec)
    .update(`${timestamp}.${row.payload}`)
    .digest('hex');

  const headers = {
    'content-type': 'application/json',
    'user-agent': `PayGate/${VERSION}`,
    'x-paygate-signature': `sha256=${signature}`,
    'x-paygate-timestamp': timestamp,
    'x-paygate-event': row.event,
    'x-paygate-event-id': row.event_id,
    'x-paygate-delivery-attempt': String(row.attempts + 1),
  };
  if (row.payment_id) headers['x-paygate-payment-id'] = row.payment_id;

  let statusCode = null;
  try {
    const response = await fetch(target, {
      method: 'POST',
      headers,
      body: row.payload,
      redirect: 'manual',
      signal: AbortSignal.timeout(config.webhook.timeoutMs),
    });
    statusCode = response.status;
    const responseText = await drainOnce(response);

    if (statusCode >= 200 && statusCode < 300) {
      stmt.outboxDelivered.run(row.attempts + 1, statusCode, nowMs(), row.id);
      log('info', 'webhook delivered', {
        outbox_id: row.id,
        event: row.event,
        app_id: row.app_id,
        status: statusCode,
      });
      return;
    }

    scheduleRetry(row, statusCode, `HTTP ${statusCode}${responseText ? `: ${responseText.slice(0, 200)}` : ''}`, now);
  } catch (err) {
    const message = err && err.name === 'TimeoutError' ? 'request timed out' : String((err && err.message) || err);
    scheduleRetry(row, statusCode, message, now);
  }
}

function scheduleRetry(row, statusCode, error, now) {
  const attempts = row.attempts + 1;
  if (attempts >= config.webhook.maxAttempts) {
    stmt.outboxFailed.run(attempts, statusCode, String(error).slice(0, 500), row.id);
    log('warn', 'webhook failed permanently', {
      outbox_id: row.id,
      event: row.event,
      app_id: row.app_id,
      attempts,
      error: String(error).slice(0, 200),
    });
    return;
  }

  const base = RETRY_DELAYS_MS[Math.min(attempts - 1, RETRY_DELAYS_MS.length - 1)];
  const jitter = Math.floor(base * 0.2 * Math.random());
  stmt.outboxRetry.run(
    attempts,
    statusCode,
    String(error).slice(0, 500),
    now + base + jitter,
    row.id
  );
  log('warn', 'webhook delivery failed, will retry', {
    outbox_id: row.id,
    event: row.event,
    attempts,
    status: statusCode,
    error: String(error).slice(0, 200),
  });
}

async function drainOutbox() {
  const rows = stmt.outboxDue.all(nowMs(), config.webhook.batchSize);
  if (rows.length === 0) return 0;

  let cursor = 0;
  const workers = Array.from(
    { length: Math.min(config.webhook.concurrency, rows.length) },
    async () => {
      while (cursor < rows.length) {
        const row = rows[cursor++];
        const claimed = stmt.claimOutbox.run(nowMs() + 60_000, row.id);
        if (claimed.changes !== 1) continue;
        try {
          await deliverOutboxRow(row);
        } catch (err) {
          // Never leave a row stuck in 'delivering'.
          log('error', 'outbox delivery crashed', {
            outbox_id: row.id,
            error: String((err && err.message) || err),
          });
          stmt.outboxRetry.run(
            row.attempts + 1,
            null,
            String((err && err.message) || err).slice(0, 500),
            nowMs() + RETRY_DELAYS_MS[0],
            row.id
          );
        }
      }
    }
  );

  await Promise.all(workers);
  return rows.length;
}

let outboxTimer = null;
let outboxRunning = false;
let shuttingDown = false;

function scheduleOutbox(delay) {
  if (shuttingDown) return;
  outboxTimer = setTimeout(runOutboxLoop, delay);
}

async function runOutboxLoop() {
  if (shuttingDown) return;
  if (outboxRunning) {
    scheduleOutbox(1000);
    return;
  }

  outboxRunning = true;
  let nextDelay = config.webhook.idleMs;
  try {
    const processed = await drainOutbox();
    if (processed >= config.webhook.batchSize) nextDelay = 100;
    else if (processed > 0) nextDelay = 500;
  } catch (err) {
    log('error', 'outbox loop error', { error: String((err && err.message) || err) });
    nextDelay = 5000;
  } finally {
    outboxRunning = false;
  }

  // Recursive setTimeout: a new timer only after the previous run settles, so
  // a slow webhook endpoint can never stack up overlapping drains.
  scheduleOutbox(nextDelay);
}

/* -------------------------------------------------------------------------- *
 * Maintenance
 * -------------------------------------------------------------------------- */

let maintenanceTimer = null;
let lastPruneAt = 0;

function runMaintenance() {
  const now = nowMs();

  // Re-queue outbox rows whose delivery lease expired (e.g. after a crash).
  try {
    const requeued = stmt.outboxResetStale.run(now);
    if (requeued.changes > 0) {
      log('warn', 'requeued stalled webhook deliveries', { count: requeued.changes });
    }
  } catch (err) {
    log('error', 'failed to reset stalled webhook deliveries', {
      error: String((err && err.message) || err),
    });
  }

  const overdue = stmt.paymentsToExpire.all(now);
  for (const row of overdue) {
    try {
      expirePaymentTx.immediate(row.id);
    } catch (err) {
      log('error', 'failed to expire payment', {
        payment_id: row.id,
        error: String((err && err.message) || err),
      });
    }
  }

  if (now - lastPruneAt > 3_600_000) {
    lastPruneAt = now;
    const smsCutoff = now - config.smsRetentionDays * 86_400_000;
    const outboxCutoff = now - config.webhook.retentionDays * 86_400_000;
    try {
      const smsEvents = stmt.pruneSmsEvents.run(smsCutoff);
      const outbox = stmt.pruneOutbox.run(outboxCutoff);
      const unmatched = stmt.pruneUnmatchedSms.run(smsCutoff);
      if (smsEvents.changes || outbox.changes || unmatched.changes) {
        log('debug', 'retention prune complete', {
          sms_events: smsEvents.changes,
          outbox: outbox.changes,
          unmatched_sms: unmatched.changes,
        });
      }
    } catch (err) {
      log('error', 'retention prune failed', { error: String((err && err.message) || err) });
    }
  }
}

/* -------------------------------------------------------------------------- *
 * Rate limiting (in-memory, per process)
 * -------------------------------------------------------------------------- */

function createRateLimiter({ windowMs, max, name }) {
  const buckets = new Map();

  const cleanup = setInterval(() => {
    const now = nowMs();
    for (const [key, bucket] of buckets) {
      if (bucket.resetAt <= now) buckets.delete(key);
    }
  }, windowMs);
  cleanup.unref();

  return function rateLimit(req, res, next) {
    const key = `${name}:${req.ip || req.socket.remoteAddress || 'unknown'}`;
    const now = nowMs();
    let bucket = buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      bucket = { count: 0, resetAt: now + windowMs };
      buckets.set(key, bucket);
    }
    bucket.count += 1;

    const remaining = Math.max(0, max - bucket.count);
    res.set('X-RateLimit-Limit', String(max));
    res.set('X-RateLimit-Remaining', String(remaining));

    if (bucket.count > max) {
      res.set('Retry-After', String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000))));
      return fail(res, 429, 'rate_limited', 'Too many requests, please slow down.');
    }
    next();
  };
}

/* -------------------------------------------------------------------------- *
 * Express app
 * -------------------------------------------------------------------------- */

const app = express();
app.disable('x-powered-by');
if (config.trustProxy !== false) app.set('trust proxy', config.trustProxy);

app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('X-Permitted-Cross-Domain-Policies', 'none');
  next();
});

app.use('/api', express.json({ limit: '128kb' }));
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});

function bearerToken(req) {
  const header = req.get('authorization') || '';
  if (/^Bearer\s+/i.test(header)) return header.replace(/^Bearer\s+/i, '').trim();
  return '';
}

function requireAdmin(req, res, next) {
  const provided = (req.get('x-admin-key') || '').trim() || bearerToken(req);
  if (!provided || !timingSafeEqualStr(provided, config.adminKey)) {
    return fail(res, 401, 'unauthorized', 'Invalid admin API key.');
  }
  next();
}

function requireApp(req, res, next) {
  const key = (req.get('x-api-key') || '').trim() || bearerToken(req);
  if (!key) return fail(res, 401, 'missing_api_key', 'Provide your pk_ key as a Bearer token.');
  const appRow = stmt.appByKey.get(key);
  if (!appRow) return fail(res, 401, 'invalid_api_key', 'Unknown API key.');
  if (!appRow.active) return fail(res, 403, 'app_disabled', 'This app is disabled.');
  req.appRecord = appRow;
  next();
}

/* ------------------------------- health ---------------------------------- */

app.get('/', (req, res) => {
  res.json({ name: 'PayGate', version: VERSION, status: 'ok' });
});

app.get('/healthz', (req, res) => {
  try {
    db.prepare('SELECT 1').get();
    res.json({ status: 'ok', version: VERSION, uptime_seconds: Math.floor(process.uptime()) });
  } catch (err) {
    res.status(503).json({ status: 'error', message: 'database unavailable' });
  }
});

/* ------------------------------- devices --------------------------------- */

app.post('/api/admin/devices', requireAdmin, (req, res) => {
  const body = req.body || {};
  const name = cleanString(body.name, 1, 80);
  const type = cleanString(body.type, 1, 10);
  const phone = normalizePhone(body.phone_number);

  if (!name) return fail(res, 400, 'invalid_name', 'name is required (1-80 characters).');
  if (!type || !['bkash', 'nagad'].includes(type.toLowerCase())) {
    return fail(res, 400, 'invalid_type', "type must be 'bkash' or 'nagad'.");
  }
  if (!phone) {
    return fail(res, 400, 'invalid_phone_number', 'phone_number must be a valid Bangladeshi mobile number.');
  }

  const now = nowMs();
  const token = randomHex(24);
  const info = stmt.insertDevice.run(name, type.toLowerCase(), phone, token, now, now);
  const device = stmt.deviceById.get(info.lastInsertRowid);
  log('info', 'device created', { device_id: device.id, type: device.type });
  res.status(201).json({ device: serializeDevice(device, baseUrl(req)) });
});

app.get('/api/admin/devices', requireAdmin, (req, res) => {
  const base = baseUrl(req);
  res.json({ object: 'list', data: stmt.devicesAll.all().map((d) => serializeDevice(d, base)) });
});

app.patch('/api/admin/devices/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return fail(res, 400, 'invalid_id', 'Invalid device id.');
  const device = stmt.deviceById.get(id);
  if (!device) return fail(res, 404, 'device_not_found', 'Device not found.');

  const body = req.body || {};
  const name = body.name === undefined ? device.name : cleanString(body.name, 1, 80);
  const phone = body.phone_number === undefined ? device.phone_number : normalizePhone(body.phone_number);
  const active = parseActive(body.active, device.active);
  const token = body.rotate_token ? randomHex(24) : device.webhook_token;

  if (!name) return fail(res, 400, 'invalid_name', 'name must be 1-80 characters.');
  if (!phone) return fail(res, 400, 'invalid_phone_number', 'phone_number must be a valid Bangladeshi mobile number.');

  stmt.updateDevice.run(name, phone, active, token, nowMs(), id);
  res.json({ device: serializeDevice(stmt.deviceById.get(id), baseUrl(req)) });
});

app.delete('/api/admin/devices/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return fail(res, 400, 'invalid_id', 'Invalid device id.');
  const device = stmt.deviceById.get(id);
  if (!device) return fail(res, 404, 'device_not_found', 'Device not found.');

  const linked = stmt.appsUsingDevice.all(id, id);
  if (linked.length > 0 && req.query.force !== '1') {
    return fail(res, 409, 'device_in_use', 'Device is linked to one or more apps. Unlink it or pass ?force=1.', {
      apps: linked,
    });
  }

  stmt.deleteDevice.run(id);
  res.json({ deleted: true, id });
});

/* -------------------------------- apps ----------------------------------- */

function resolveDeviceForApp(rawId, expectedType, excludeAppId = null) {
  if (rawId === null || rawId === undefined || rawId === '') return { id: null };
  const id = Number(rawId);
  if (!Number.isInteger(id) || id <= 0) return { error: 'invalid_device_id', status: 400 };
  const device = stmt.deviceById.get(id);
  if (!device) return { error: 'device_not_found', status: 400 };
  if (device.type !== expectedType) return { error: 'device_type_mismatch', status: 400 };

  // A merchant number may only feed one tenant: otherwise an SMS could settle
  // another app's checkout.
  const owner = stmt.appUsingDeviceExcept.get(id, id, excludeAppId === null ? -1 : excludeAppId);
  if (owner) {
    return {
      error: 'device_already_linked',
      status: 409,
      details: { app_id: owner.id, app_name: owner.name },
    };
  }

  return { id: device.id };
}

function deviceLinkError(res, result, field) {
  const messages = {
    invalid_device_id: `${field} must be a positive integer.`,
    device_not_found: `${field} does not exist.`,
    device_type_mismatch: `${field} has the wrong device type.`,
    device_already_linked: `${field} is already linked to another app.`,
  };
  return fail(res, result.status || 400, result.error, messages[result.error] || `Invalid ${field}.`, result.details);
}

app.post('/api/admin/apps', requireAdmin, (req, res) => {
  const body = req.body || {};
  const name = cleanString(body.name, 1, 80);
  if (!name) return fail(res, 400, 'invalid_name', 'name is required (1-80 characters).');

  const webhookUrl = body.webhook_url ? normalizeHttpUrl(body.webhook_url) : null;
  if (body.webhook_url && !webhookUrl) {
    return fail(res, 400, 'invalid_webhook_url', 'webhook_url must be an absolute http(s) URL.');
  }
  if (webhookUrl && !config.webhook.allowPrivateUrls && isPrivateHost(new URL(webhookUrl).hostname)) {
    return fail(res, 400, 'invalid_webhook_url', 'webhook_url must not point to a private network.');
  }

  const returnUrl = body.return_url ? normalizeHttpUrl(body.return_url) : null;
  if (body.return_url && !returnUrl) {
    return fail(res, 400, 'invalid_return_url', 'return_url must be an absolute http(s) URL.');
  }

  const bkash = resolveDeviceForApp(body.bkash_device_id, 'bkash');
  const nagad = resolveDeviceForApp(body.nagad_device_id, 'nagad');
  if (bkash.error) return deviceLinkError(res, bkash, 'bkash_device_id');
  if (nagad.error) return deviceLinkError(res, nagad, 'nagad_device_id');
  if (bkash.id && nagad.id && bkash.id === nagad.id) {
    return fail(res, 400, 'duplicate_device', 'bkash_device_id and nagad_device_id must differ.');
  }

  const now = nowMs();
  const info = stmt.insertApp.run(
    name,
    `pk_${randomHex(18)}`,
    `whsec_${randomHex(32)}`,
    webhookUrl,
    returnUrl,
    bkash.id,
    nagad.id,
    now,
    now
  );
  const appRow = stmt.appById.get(info.lastInsertRowid);
  log('info', 'app created', { app_id: appRow.id, has_bkash: Boolean(bkash.id), has_nagad: Boolean(nagad.id) });
  res.status(201).json({ app: serializeApp(appRow) });
});

app.get('/api/admin/apps', requireAdmin, (req, res) => {
  res.json({ object: 'list', data: stmt.appsAll.all().map(serializeApp) });
});

app.patch('/api/admin/apps/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return fail(res, 400, 'invalid_id', 'Invalid app id.');
  const appRow = stmt.appById.get(id);
  if (!appRow) return fail(res, 404, 'app_not_found', 'App not found.');

  const body = req.body || {};
  const name = body.name === undefined ? appRow.name : cleanString(body.name, 1, 80);
  if (!name) return fail(res, 400, 'invalid_name', 'name must be 1-80 characters.');

  let webhookUrl = appRow.webhook_url;
  if (body.webhook_url !== undefined) {
    webhookUrl = body.webhook_url === null || body.webhook_url === '' ? null : normalizeHttpUrl(body.webhook_url);
    if (body.webhook_url && !webhookUrl) {
      return fail(res, 400, 'invalid_webhook_url', 'webhook_url must be an absolute http(s) URL.');
    }
    if (webhookUrl && !config.webhook.allowPrivateUrls && isPrivateHost(new URL(webhookUrl).hostname)) {
      return fail(res, 400, 'invalid_webhook_url', 'webhook_url must not point to a private network.');
    }
  }

  let returnUrl = appRow.return_url;
  if (body.return_url !== undefined) {
    returnUrl = body.return_url === null || body.return_url === '' ? null : normalizeHttpUrl(body.return_url);
    if (body.return_url && !returnUrl) {
      return fail(res, 400, 'invalid_return_url', 'return_url must be an absolute http(s) URL.');
    }
  }

  const bkash = body.bkash_device_id === undefined
    ? { id: appRow.bkash_device_id }
    : resolveDeviceForApp(body.bkash_device_id, 'bkash', id);
  const nagad = body.nagad_device_id === undefined
    ? { id: appRow.nagad_device_id }
    : resolveDeviceForApp(body.nagad_device_id, 'nagad', id);
  if (bkash.error) return deviceLinkError(res, bkash, 'bkash_device_id');
  if (nagad.error) return deviceLinkError(res, nagad, 'nagad_device_id');
  if (bkash.id && nagad.id && bkash.id === nagad.id) {
    return fail(res, 400, 'duplicate_device', 'bkash_device_id and nagad_device_id must differ.');
  }

  const active = parseActive(body.active, appRow.active);
  const rotate = Boolean(body.rotate_keys);
  const pkKey = rotate ? `pk_${randomHex(18)}` : appRow.pk_key;
  const whsec = rotate ? `whsec_${randomHex(32)}` : appRow.whsec;

  stmt.updateApp.run(
    name,
    pkKey,
    whsec,
    webhookUrl,
    returnUrl,
    bkash.id,
    nagad.id,
    active,
    nowMs(),
    id
  );

  if (rotate) log('info', 'app keys rotated', { app_id: id });
  res.json({ app: serializeApp(stmt.appById.get(id)) });
});

app.delete('/api/admin/apps/:id', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return fail(res, 400, 'invalid_id', 'Invalid app id.');
  const appRow = stmt.appById.get(id);
  if (!appRow) return fail(res, 404, 'app_not_found', 'App not found.');
  if (req.query.force !== '1') {
    return fail(res, 409, 'confirmation_required', 'Deleting an app removes its payments and webhooks. Pass ?force=1 to confirm.');
  }
  stmt.deleteApp.run(id);
  log('info', 'app deleted', { app_id: id });
  res.json({ deleted: true, id });
});

/* ------------------------------ payments --------------------------------- */

app.post('/api/payments', requireApp, (req, res) => {
  const tenant = req.appRecord;
  const body = req.body || {};

  const amountPoisha = parseMoneyToPoisha(body.amount);
  if (!amountPoisha) {
    return fail(res, 400, 'invalid_amount', 'amount must be a positive BDT value with at most 2 decimals.');
  }
  if (amountPoisha > config.maxPaymentPoisha) {
    return fail(res, 400, 'amount_too_large', `amount exceeds the maximum of ${formatAmount(config.maxPaymentPoisha)} BDT.`);
  }

  let returnUrl = tenant.return_url;
  if (body.return_url !== undefined && body.return_url !== null && body.return_url !== '') {
    returnUrl = normalizeHttpUrl(body.return_url);
    if (!returnUrl) return fail(res, 400, 'invalid_return_url', 'return_url must be an absolute http(s) URL.');
  }

  let senderNumber = null;
  if (body.sender_number !== undefined && body.sender_number !== null && body.sender_number !== '') {
    senderNumber = normalizePhone(body.sender_number);
    if (!senderNumber) {
      return fail(res, 400, 'invalid_sender_number', 'sender_number must be a valid Bangladeshi mobile number.');
    }
  }

  let metadata = null;
  if (body.metadata !== undefined && body.metadata !== null) {
    if (typeof body.metadata !== 'object' || Array.isArray(body.metadata)) {
      return fail(res, 400, 'invalid_metadata', 'metadata must be a JSON object.');
    }
    metadata = JSON.stringify(body.metadata);
    if (metadata.length > 8192) return fail(res, 400, 'invalid_metadata', 'metadata is too large (max 8 KB).');
  }

  const ttlSeconds = clampInt(body.expires_in, 60, 604800, config.paymentTtlSeconds);

  const bkashDevice = tenant.bkash_device_id ? stmt.deviceById.get(tenant.bkash_device_id) : null;
  const nagadDevice = tenant.nagad_device_id ? stmt.deviceById.get(tenant.nagad_device_id) : null;
  const methods = [];
  if (bkashDevice && bkashDevice.active && bkashDevice.phone_number) {
    methods.push({
      type: 'bkash',
      label: 'bKash',
      number: displayPhone(bkashDevice.phone_number),
    });
  }
  if (nagadDevice && nagadDevice.active && nagadDevice.phone_number) {
    methods.push({
      type: 'nagad',
      label: 'Nagad',
      number: displayPhone(nagadDevice.phone_number),
    });
  }
  if (methods.length === 0) {
    return fail(res, 400, 'no_active_device', 'This app has no active payment device linked.');
  }

  const now = nowMs();
  const id = `pay_${randomHex(12)}`;
  stmt.insertPayment.run(
    id,
    tenant.id,
    amountPoisha,
    senderNumber,
    returnUrl,
    metadata,
    now,
    now + ttlSeconds * 1000,
    now
  );

  const payment = stmt.paymentById.get(id);
  log('info', 'payment created', { payment_id: id, app_id: tenant.id, amount_poisha: amountPoisha });

  res.status(201).json({
    payment: serializePayment(payment, baseUrl(req)),
    checkout_url: `${baseUrl(req)}/pay/${payment.id}`,
    payment_methods: methods,
  });
});

app.get('/api/payments', requireApp, (req, res) => {
  const limit = clampInt(req.query.limit, 1, 100, 25);
  const offset = clampInt(req.query.offset, 0, 10_000_000, 0);
  const status = typeof req.query.status === 'string' && req.query.status ? req.query.status : null;

  if (status && !['pending', 'success', 'expired', 'cancelled'].includes(status)) {
    return fail(res, 400, 'invalid_status', 'status must be one of pending, success, expired, cancelled.');
  }

  const rows = status
    ? stmt.paymentsByAppStatus.all(req.appRecord.id, status, limit, offset)
    : stmt.paymentsByApp.all(req.appRecord.id, limit, offset);

  const base = baseUrl(req);
  res.json({
    object: 'list',
    data: rows.map((p) => serializePayment(p, base)),
    has_more: rows.length === limit,
    limit,
    offset,
  });
});

app.get('/api/payments/:id', requireApp, (req, res) => {
  const payment = stmt.paymentById.get(req.params.id);
  if (!payment || payment.app_id !== req.appRecord.id) {
    return fail(res, 404, 'payment_not_found', 'Payment not found.');
  }
  const current = expireIfNeeded(payment);
  res.json({ payment: serializePayment(current, baseUrl(req)) });
});

app.post('/api/payments/:id/cancel', requireApp, (req, res) => {
  const payment = stmt.paymentById.get(req.params.id);
  if (!payment || payment.app_id !== req.appRecord.id) {
    return fail(res, 404, 'payment_not_found', 'Payment not found.');
  }
  const changed = stmt.cancelPayment.run(nowMs(), payment.id);
  if (changed.changes !== 1) {
    return fail(res, 409, 'payment_not_pending', `Payment is already ${payment.status}.`);
  }
  res.json({ payment: serializePayment(stmt.paymentById.get(payment.id), baseUrl(req)) });
});

/* --------------------------- public endpoints ---------------------------- */

const publicLimiter = createRateLimiter({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.publicMax,
  name: 'public',
});

app.get('/api/public/payments/:id', publicLimiter, (req, res) => {
  let payment = stmt.paymentById.get(req.params.id);
  if (!payment) return fail(res, 404, 'payment_not_found', 'Payment not found.');
  payment = expireIfNeeded(payment);

  res.set('Access-Control-Allow-Origin', '*');
  res.set('Cache-Control', 'no-store');
  res.json({
    ...serializePublicPayment(payment),
    redirect_url: payment.status === 'success' ? buildReturnUrl(payment.return_url, payment) : null,
  });
});

app.options('/api/public/payments/:id', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.set('Access-Control-Allow-Headers', 'Accept, Content-Type');
  res.status(204).end();
});

/* ------------------------------- checkout -------------------------------- */

function renderErrorPage(title, message) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex,nofollow" />
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         background: #f4f5f8; color: #14161a; }
  .box { width: 100%; max-width: 420px; background: #fff; border-radius: 18px; padding: 32px;
         box-shadow: 0 12px 40px rgba(20, 22, 26, .08); text-align: center; }
  h1 { font-size: 20px; margin: 0 0 10px; }
  p { margin: 0; color: #5b6170; line-height: 1.55; font-size: 14px; }
  .icon { width: 48px; height: 48px; border-radius: 50%; background: #fdecec; color: #d7263d;
          display: grid; place-items: center; font-size: 24px; margin: 0 auto 18px; font-weight: 700; }
</style></head>
<body><div class="box"><div class="icon">!</div><h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></div></body></html>`;
}

function activePaymentMethods(appRow) {
  const methods = [];
  if (appRow.bkash_device_id) {
    const device = stmt.deviceById.get(appRow.bkash_device_id);
    if (device && device.active && device.phone_number) {
      methods.push({ type: 'bkash', label: 'bKash', number: displayPhone(device.phone_number) });
    }
  }
  if (appRow.nagad_device_id) {
    const device = stmt.deviceById.get(appRow.nagad_device_id);
    if (device && device.active && device.phone_number) {
      methods.push({ type: 'nagad', label: 'Nagad', number: displayPhone(device.phone_number) });
    }
  }
  return methods;
}

function renderCheckoutPage({ payment, appRow, methods, redirectUrl }) {
  const amount = formatAmount(payment.amount_poisha);
  const appName = appRow.name.length > 60 ? `${appRow.name.slice(0, 57)}...` : appRow.name;

  const methodsHtml = methods
    .map((method) => {
      const cls = method.type === 'bkash' ? 'bkash' : 'nagad';
      return `<div class="method ${cls}">
        <div class="method-head">
          <span class="dot"></span>
          <span class="method-name">${escapeHtml(method.label)}</span>
          <span class="method-tag">Send Money</span>
        </div>
        <div class="number-row">
          <span class="number">${escapeHtml(method.number)}</span>
          <button type="button" class="copy" data-copy="${escapeHtml(method.number)}">Copy</button>
        </div>
      </div>`;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex,nofollow" />
<title>Pay ${BDT}${amount} \u00B7 ${escapeHtml(appName)}</title>
<style>
  :root { color-scheme: light; --ink: #14161a; --muted: #5b6170; --line: #e7e9ef; --bg: #f4f5f8; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; padding: 28px 16px 40px; background: var(--bg); color: var(--ink);
         font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
         -webkit-font-smoothing: antialiased; }
  .wrap { width: 100%; max-width: 460px; margin: 0 auto; }
  .card { background: #fff; border-radius: 20px; box-shadow: 0 14px 44px rgba(20, 22, 26, .09); overflow: hidden; }
  .top { display: flex; align-items: center; justify-content: space-between; gap: 12px;
         padding: 18px 22px; border-bottom: 1px solid var(--line); }
  .merchant { font-weight: 650; font-size: 15px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .badge { flex: none; font-size: 11px; letter-spacing: .04em; text-transform: uppercase;
           color: #1b7f4d; background: #e8f7ef; border-radius: 999px; padding: 5px 10px; font-weight: 650; }
  .amount-block { padding: 26px 22px 8px; text-align: center; }
  .label { font-size: 12px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); font-weight: 600; }
  .amount { font-size: 40px; font-weight: 750; letter-spacing: -.02em; margin-top: 6px; }
  .order { margin-top: 6px; font-size: 12px; color: #8a90a0; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .methods { display: grid; gap: 10px; padding: 18px 22px 4px; }
  .method { border: 1px solid var(--line); border-radius: 14px; padding: 12px 14px; background: #fbfbfd; }
  .method-head { display: flex; align-items: center; gap: 8px; }
  .dot { width: 9px; height: 9px; border-radius: 50%; background: #9aa0ae; }
  .method.bkash .dot { background: #e2136e; }
  .method.nagad .dot { background: #ee7623; }
  .method-name { font-weight: 650; font-size: 14px; }
  .method-tag { margin-left: auto; font-size: 11px; color: var(--muted); background: #eef0f5;
                border-radius: 999px; padding: 3px 8px; font-weight: 600; }
  .number-row { display: flex; align-items: center; gap: 10px; margin-top: 8px; }
  .number { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 19px;
            font-weight: 650; letter-spacing: .02em; flex: 1; }
  .copy { border: 1px solid var(--line); background: #fff; color: var(--ink); border-radius: 9px;
          padding: 7px 12px; font-size: 12px; font-weight: 650; cursor: pointer; }
  .copy:hover { background: #f4f5f8; }
  .hint { margin: 16px 22px 0; padding: 11px 13px; border-radius: 11px; background: #fff8e8;
          border: 1px solid #f5e3b8; color: #7a5b12; font-size: 12.5px; line-height: 1.5; }
  .steps { padding: 14px 22px 0; }
  .step { display: flex; gap: 9px; font-size: 12.5px; color: var(--muted); line-height: 1.5; padding: 4px 0; }
  .step b { color: var(--ink); font-weight: 650; }
  .step-num { flex: none; width: 18px; height: 18px; border-radius: 50%; background: #eef0f5; color: var(--ink);
              font-size: 11px; font-weight: 700; display: grid; place-items: center; margin-top: 1px; }
  .status { display: flex; align-items: center; gap: 12px; margin: 18px 22px; padding: 14px;
            border-radius: 13px; border: 1px solid var(--line); background: #fbfbfd; }
  .status-title { font-size: 13.5px; font-weight: 650; }
  .status-sub { font-size: 12px; color: var(--muted); margin-top: 2px; line-height: 1.45; }
  .status.success { border-color: #bfe6ce; background: #f0fbf5; }
  .status.success .spinner { display: none; }
  .status.success .status-title { color: #1b7f4d; }
  .status.expired, .status.cancelled { border-color: #f0d3d3; background: #fdf4f4; }
  .status.expired .spinner, .status.cancelled .spinner { display: none; }
  .status.expired .status-title, .status.cancelled .status-title { color: #b4283c; }
  .spinner { flex: none; width: 20px; height: 20px; border-radius: 50%;
             border: 2.5px solid #dfe2ea; border-top-color: #3b63f6; animation: spin .9s linear infinite; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .countdown { font-variant-numeric: tabular-nums; font-weight: 650; color: var(--ink); }
  .foot { padding: 0 22px 18px; text-align: center; font-size: 11px; color: #9aa0ae; }
  .foot b { color: #6b7280; font-weight: 650; }
  @media (max-width: 380px) { .amount { font-size: 34px; } }
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <div class="top">
      <div class="merchant">${escapeHtml(appName)}</div>
      <div class="badge">Secure checkout</div>
    </div>

    <div class="amount-block">
      <div class="label">Amount to send</div>
      <div class="amount">${BDT}${amount}</div>
      <div class="order">${escapeHtml(payment.id)}</div>
    </div>

    <div class="methods">
${methodsHtml}
    </div>

    <div class="hint">
      Send the <b>exact amount</b> from your own number. Payments are confirmed automatically
      from the merchant's SMS &mdash; no screenshot or TrxID submission is needed.
    </div>

    <div class="steps">
      <div class="step"><span class="step-num">1</span><span>Open <b>bKash</b> or <b>Nagad</b> and choose <b>Send Money</b>.</span></div>
      <div class="step"><span class="step-num">2</span><span>Enter the number above and send exactly <b>${BDT}${amount}</b>.</span></div>
      <div class="step"><span class="step-num">3</span><span>Keep this page open &mdash; confirmation is automatic.</span></div>
    </div>

    <div class="status pending" id="status">
      <span class="spinner" aria-hidden="true"></span>
      <div>
        <div class="status-title" id="status-title">Waiting for your payment&hellip;</div>
        <div class="status-sub" id="status-sub">This page checks automatically every few seconds.</div>
        <div class="status-sub" id="countdown-row">Expires in <span class="countdown" id="countdown">--:--</span></div>
      </div>
    </div>

    <div class="foot">Protected by <b>PayGate</b></div>
  </div>
</div>

<script>
(function () {
  'use strict';

  var paymentId = ${jsString(payment.id)};
  var statusUrl = '/api/public/payments/' + encodeURIComponent(paymentId);
  var redirectUrl = ${jsString(redirectUrl)};
  var expiresAt = ${Number(payment.expires_at)};
  var initialStatus = ${jsString(payment.status)};
  var initialTrx = ${jsString(payment.trx_id || null)};

  var finished = false;
  var pollTimer = null;
  var countdownTimer = null;

  function byId(id) { return document.getElementById(id); }

  function setStatus(state, title, sub) {
    var box = byId('status');
    box.className = 'status ' + state;
    byId('status-title').textContent = title;
    byId('status-sub').textContent = sub || '';
    byId('countdown-row').style.display = state === 'pending' ? '' : 'none';
  }

  function stopTimers() {
    if (pollTimer) { clearTimeout(pollTimer); pollTimer = null; }
    if (countdownTimer) { clearInterval(countdownTimer); countdownTimer = null; }
  }

  function finishSuccess(trxId, targetUrl) {
    if (finished) return;
    finished = true;
    stopTimers();
    setStatus('success', 'Payment received',
      trxId ? 'Transaction ID: ' + trxId : 'Your payment has been confirmed.');
    var target = targetUrl || redirectUrl;
    if (target) {
      setTimeout(function () { window.location.replace(target); }, 1200);
    }
  }

  function finishExpired() {
    if (finished) return;
    finished = true;
    stopTimers();
    setStatus('expired', 'Payment request expired',
      'No matching payment was received in time. Please start a new checkout from the app.');
  }

  function finishCancelled() {
    if (finished) return;
    finished = true;
    stopTimers();
    setStatus('cancelled', 'Payment cancelled',
      'This checkout was cancelled. Please start a new payment from the app.');
  }

  function tick() {
    var left = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
    var minutes = Math.floor(left / 60);
    var seconds = left % 60;
    byId('countdown').textContent =
      (minutes < 10 ? '0' : '') + minutes + ':' + (seconds < 10 ? '0' : '') + seconds;
  }

  function poll() {
    if (finished) return;
    fetch(statusUrl, { cache: 'no-store', headers: { accept: 'application/json' } })
      .then(function (response) {
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return response.json();
      })
      .then(function (data) {
        if (finished) return;
        if (data.status === 'success') return finishSuccess(data.trx_id, data.redirect_url);
        if (data.status === 'expired') return finishExpired();
        if (data.status === 'cancelled') return finishCancelled();
        pollTimer = setTimeout(poll, 4000);
      })
      .catch(function () {
        if (!finished) pollTimer = setTimeout(poll, 4000);
      });
  }

  Array.prototype.forEach.call(document.querySelectorAll('[data-copy]'), function (button) {
    button.addEventListener('click', function () {
      var value = button.getAttribute('data-copy');
      var restore = function () {
        button.textContent = 'Copy';
      };
      var done = function () {
        button.textContent = 'Copied';
        setTimeout(restore, 1500);
      };
      var fallback = function () {
        var area = document.createElement('textarea');
        area.value = value;
        area.setAttribute('readonly', '');
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.body.appendChild(area);
        area.select();
        try { document.execCommand('copy'); done(); } catch (err) { /* ignore */ }
        document.body.removeChild(area);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(done, fallback);
      } else {
        fallback();
      }
    });
  });

  if (initialStatus === 'success') {
    finishSuccess(initialTrx, redirectUrl);
  } else if (initialStatus === 'expired') {
    finishExpired();
  } else if (initialStatus === 'cancelled') {
    finishCancelled();
  } else {
    tick();
    countdownTimer = setInterval(tick, 1000);
    pollTimer = setTimeout(poll, 4000);
  }
})();
</script>
</body>
</html>`;
}

app.get('/pay/:id', (req, res) => {
  const payment = stmt.paymentById.get(req.params.id);
  if (!payment) {
    return res
      .status(404)
      .type('html')
      .send(renderErrorPage('Checkout not found', 'This payment link is invalid or has been removed.'));
  }

  const appRow = stmt.appById.get(payment.app_id);
  if (!appRow || !appRow.active) {
    return res
      .status(410)
      .type('html')
      .send(renderErrorPage('Checkout unavailable', 'This merchant is no longer accepting payments.'));
  }

  const current = expireIfNeeded(payment);
  const methods = activePaymentMethods(appRow);
  if (methods.length === 0 && current.status === 'pending') {
    return res
      .status(503)
      .type('html')
      .send(renderErrorPage('Payments unavailable', 'This merchant has no active payment number right now.'));
  }

  res.set('Cache-Control', 'no-store');
  res.set('Content-Security-Policy', [
    "default-src 'none'",
    "style-src 'unsafe-inline'",
    "script-src 'unsafe-inline'",
    "connect-src 'self'",
    "img-src data:",
    "base-uri 'none'",
    "form-action 'none'",
  ].join('; '));
  res.type('html').send(
    renderCheckoutPage({
      payment: current,
      appRow,
      methods,
      redirectUrl: current.status === 'success' ? buildReturnUrl(current.return_url, current) : null,
    })
  );
});

/* ----------------------------- SMS webhook ------------------------------- */

const SMS_TEXT_KEYS = [
  'message', 'text', 'msg', 'body', 'sms', 'content', 'sms_text', 'smstext', 'messagebody', 'message_body',
];
const SMS_SENDER_KEYS = [
  'sender', 'from', 'address', 'msisdn', 'phone', 'phonenumber', 'phone_number', 'sendernumber',
  'sender_number', 'originator', 'mobile',
];
const SMS_TRX_KEYS = [
  'trx_id', 'trxid', 'trx', 'transaction_id', 'transactionid', 'txn_id', 'txnid', 'txid', 'reference',
  'ref', 'transaction_ref',
];
const SMS_AMOUNT_KEYS = ['amount', 'value', 'taka', 'tk', 'amount_bdt'];

function collectFields(data, query) {
  const out = {};
  const merge = (obj) => {
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      for (const [key, value] of Object.entries(obj)) out[key] = value;
    }
  };
  merge(data);
  if (data && typeof data === 'object') {
    merge(data.data);
    merge(data.payload);
  }
  merge(query);
  const lowered = {};
  for (const [key, value] of Object.entries(out)) lowered[key.toLowerCase()] = value;
  return lowered;
}

function pickField(fields, keys) {
  for (const key of keys) {
    const value = fields[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
    if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  }
  return null;
}

function parseWebhookBody(req, rawBody) {
  const contentType = (req.get('content-type') || '').toLowerCase();
  const raw = rawBody.trim();
  let data = null;

  if (contentType.includes('json') || raw.startsWith('{') || raw.startsWith('[')) {
    try {
      data = JSON.parse(raw);
    } catch {
      data = null;
    }
  } else if (contentType.includes('urlencoded') || /^[^=&\s]+=[^\s]*(&[^=&\s]+=[^\s]*)*$/.test(raw)) {
    try {
      data = Object.fromEntries(new URLSearchParams(raw));
    } catch {
      data = null;
    }
  }

  if (data === null) {
    // Some forwarders post the SMS as a raw text/plain body.
    data = raw ? { text: raw } : {};
  }

  return data;
}

function parseAmountFromText(text) {
  if (!text) return null;
  const pattern = /(?:tk\.?|bdt|\u09F3)\s*:?\s*([0-9][0-9,]*(?:\.[0-9]{1,2})?)/gi;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    const before = text.slice(Math.max(0, match.index - 32), match.index).toLowerCase();
    if (/balance|new bal|available/.test(before)) continue;
    return parseMoneyToPoisha(match[1]);
  }
  return null;
}

function normalizeTrxId(value) {
  if (!value) return null;
  const cleaned = String(value).trim().replace(/^[#:\-\s]+|[#:\-\s]+$/g, '').replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z0-9]{6,32}$/.test(cleaned)) return null;
  if (!/\d/.test(cleaned)) return null;
  return cleaned;
}

function parseTrxIdFromText(text) {
  if (!text) return null;
  const match = text.match(
    /(?:trx\s*id|trxid|transaction\s*id|txn\s*id|txid|reference|ref)\s*(?:no\.?)?\s*[:\-#]?\s*([A-Za-z0-9]{6,32})/i
  );
  return match ? normalizeTrxId(match[1]) : null;
}

function parseSenderFromText(text, ownNumber) {
  if (!text) return null;
  const own = normalizePhone(ownNumber);

  const labelled = text.match(/(?:from|sender|mobile)\s*[:\-]?\s*(\+?\d{10,15})/i);
  if (labelled) {
    const normalized = normalizePhone(labelled[1]);
    if (normalized && normalized !== own) return normalized;
  }

  const pattern = /(\+?8801[3-9]\d{8}|01[3-9]\d{8})/g;
  let match;
  while ((match = pattern.exec(text)) !== null) {
    const normalized = normalizePhone(match[1]);
    if (normalized && normalized !== own) return normalized;
  }
  return null;
}

function updateSmsEvent(eventId, status, error, trxId, paymentId) {
  stmt.updateSmsEvent.run(status, error || null, trxId || null, paymentId || null, eventId);
}

const webhookLimiter = createRateLimiter({
  windowMs: config.rateLimit.windowMs,
  max: config.rateLimit.webhookMax,
  name: 'webhook',
});

const rawBodyParser = express.raw({ type: '*/*', limit: '256kb' });

function handleSmsWebhook(req, res) {
  const device = stmt.deviceByToken.get(req.params.token);
  if (!device) return res.status(404).json({ ok: false, error: 'unknown_device' });
  if (!device.active) return res.status(403).json({ ok: false, error: 'device_inactive' });

  const rawBody = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : '';
  const query = req.query && typeof req.query === 'object' ? req.query : {};
  const hasQuery = Object.keys(query).length > 0;
  if (!rawBody.trim() && !hasQuery) {
    return res.status(400).json({ ok: false, error: 'empty_payload' });
  }
  const rawForHash = rawBody.trim() || JSON.stringify(query);

  const now = nowMs();
  stmt.touchDevice.run(now, now, device.id);

  const insertedEvent = stmt.insertSmsEvent.run(
    device.id,
    sha256(rawForHash),
    rawForHash.slice(0, 20000),
    'received',
    now
  );
  if (insertedEvent.changes === 0) {
    return res.json({ ok: true, duplicate: true, reason: 'payload_already_received' });
  }
  const eventId = Number(insertedEvent.lastInsertRowid);

  const data = parseWebhookBody(req, rawBody);
  const fields = collectFields(data, query);
  const text = pickField(fields, SMS_TEXT_KEYS) || (rawBody.trim() && !rawBody.trim().startsWith('{') ? rawBody.trim() : null);

  const explicitTrx = pickField(fields, SMS_TRX_KEYS);
  const explicitAmount = pickField(fields, SMS_AMOUNT_KEYS);
  const explicitSender = pickField(fields, SMS_SENDER_KEYS);

  const trxId = normalizeTrxId(explicitTrx) || parseTrxIdFromText(text);
  const amountPoisha = parseMoneyToPoisha(explicitAmount) || parseAmountFromText(text);
  const sender = normalizePhone(explicitSender) || parseSenderFromText(text, device.phone_number);

  if (!trxId || !amountPoisha || !sender) {
    const missing = [];
    if (!trxId) missing.push('trx_id');
    if (!amountPoisha) missing.push('amount');
    if (!sender) missing.push('sender');
    updateSmsEvent(eventId, 'unparseable', `missing ${missing.join(', ')}`, trxId, null);
    log('warn', 'unparseable sms', {
      device_id: device.id,
      missing,
      preview: (text || rawForHash).slice(0, 120),
    });
    return res.status(422).json({
      ok: false,
      error: 'unparseable_sms',
      missing,
      hint: 'Send JSON like {"text":"...","sender":"01XXXXXXXXX"} or include the SMS body verbatim.',
    });
  }

  if (amountPoisha > config.maxPaymentPoisha) {
    updateSmsEvent(eventId, 'ignored', 'amount above maximum', trxId, null);
    return res.status(422).json({ ok: false, error: 'amount_too_large', trx_id: trxId });
  }

  const insertedSms = stmt.insertSmsPayment.run(
    device.id,
    trxId,
    amountPoisha,
    sender,
    (text || rawForHash).slice(0, 4000),
    now,
    now
  );

  if (insertedSms.changes === 0) {
    const existing = stmt.smsPaymentByTrx.get(trxId);
    updateSmsEvent(eventId, 'duplicate', 'trx_id already recorded', trxId, existing ? existing.payment_id : null);
    log('warn', 'duplicate trx_id rejected', { device_id: device.id, trx_id: trxId });
    return res.json({
      ok: true,
      duplicate: true,
      reason: 'trx_id_already_recorded',
      trx_id: trxId,
      payment_id: existing ? existing.payment_id : null,
    });
  }

  const smsId = Number(insertedSms.lastInsertRowid);
  let result;
  try {
    result = settleSms.immediate(smsId);
  } catch (err) {
    log('error', 'sms settlement failed', {
      sms_id: smsId,
      trx_id: trxId,
      error: String((err && err.message) || err),
    });
    updateSmsEvent(eventId, 'error', String((err && err.message) || err), trxId, null);
    return res.status(500).json({ ok: false, error: 'settlement_failed' });
  }

  if (result.status === 'matched') {
    updateSmsEvent(eventId, 'matched', null, trxId, result.payment_id);
    log('info', 'payment matched', {
      payment_id: result.payment_id,
      trx_id: trxId,
      amount_poisha: amountPoisha,
      device_id: device.id,
    });
    return res.json({
      ok: true,
      matched: true,
      payment_id: result.payment_id,
      status: 'success',
      trx_id: trxId,
    });
  }

  if (result.status === 'already_matched') {
    updateSmsEvent(eventId, 'duplicate', 'sms already matched', trxId, result.payment_id);
    return res.json({
      ok: true,
      matched: true,
      duplicate: true,
      payment_id: result.payment_id,
      trx_id: trxId,
    });
  }

  updateSmsEvent(eventId, 'unmatched', 'no matching pending payment', trxId, null);
  log('info', 'sms stored but unmatched', {
    sms_id: smsId,
    trx_id: trxId,
    amount_poisha: amountPoisha,
    device_id: device.id,
  });
  return res.json({
    ok: true,
    matched: false,
    reason: 'no_matching_payment',
    trx_id: trxId,
    amount: amountPoisha / 100,
    sender_number: displayPhone(sender),
  });
}

app.post('/webhook/sms/:token', webhookLimiter, rawBodyParser, handleSmsWebhook);
app.get('/webhook/sms/:token', webhookLimiter, handleSmsWebhook);

/* ------------------------------ admin ops -------------------------------- */

app.get('/api/admin/payments', requireAdmin, (req, res) => {
  const limit = clampInt(req.query.limit, 1, 200, 50);
  const offset = clampInt(req.query.offset, 0, 10_000_000, 0);
  const status = typeof req.query.status === 'string' && req.query.status ? req.query.status : null;
  const base = baseUrl(req);

  let rows;
  if (status) {
    if (!['pending', 'success', 'expired', 'cancelled'].includes(status)) {
      return fail(res, 400, 'invalid_status', 'Invalid status filter.');
    }
    rows = stmt.paymentsAllStatus.all(status, limit, offset);
  } else {
    rows = stmt.paymentsAll.all(limit, offset);
  }

  res.json({
    object: 'list',
    data: rows.map((p) => serializePayment(p, base)),
    limit,
    offset,
    has_more: rows.length === limit,
  });
});

app.get('/api/admin/sms', requireAdmin, (req, res) => {
  const limit = clampInt(req.query.limit, 1, 200, 50);
  const onlyUnmatched = req.query.status === 'unmatched';
  const rows = onlyUnmatched ? stmt.smsUnmatched.all(limit) : stmt.smsAll.all(limit);
  res.json({
    object: 'list',
    data: rows.map((row) => ({
      id: row.id,
      object: 'sms_payment',
      device_id: row.device_id,
      device_name: row.device_name,
      device_type: row.device_type,
      trx_id: row.trx_id,
      amount: row.amount_poisha / 100,
      amount_poisha: row.amount_poisha,
      sender_number: displayPhone(row.sender_number),
      payment_id: row.payment_id,
      locked_at: iso(row.locked_at),
      received_at: iso(row.received_at),
      raw_sms: row.raw_sms,
    })),
    limit,
  });
});

app.get('/api/admin/sms/events', requireAdmin, (req, res) => {
  const limit = clampInt(req.query.limit, 1, 200, 50);
  const status = typeof req.query.status === 'string' && req.query.status ? req.query.status : null;
  const rows = status ? stmt.smsEventsByStatus.all(status, limit) : stmt.smsEventsAll.all(limit);
  res.json({
    object: 'list',
    data: rows.map((row) => ({
      id: row.id,
      object: 'sms_event',
      device_id: row.device_id,
      status: row.status,
      error: row.error,
      trx_id: row.trx_id,
      payment_id: row.payment_id,
      raw_body: row.raw_body,
      created_at: iso(row.created_at),
    })),
    limit,
  });
});

app.post('/api/admin/sms/:id/match', requireAdmin, (req, res) => {
  const smsId = Number(req.params.id);
  if (!Number.isInteger(smsId)) return fail(res, 400, 'invalid_id', 'Invalid SMS id.');
  const sms = stmt.smsPaymentById.get(smsId);
  if (!sms) return fail(res, 404, 'sms_not_found', 'SMS payment not found.');
  if (sms.payment_id) return fail(res, 409, 'sms_already_matched', 'This SMS is already matched.');

  const paymentId = cleanString((req.body || {}).payment_id, 1, 64);
  if (!paymentId) return fail(res, 400, 'invalid_payment_id', 'payment_id is required.');
  const payment = stmt.paymentById.get(paymentId);
  if (!payment) return fail(res, 404, 'payment_not_found', 'Payment not found.');
  if (payment.status !== 'pending') {
    return fail(res, 409, 'payment_not_pending', `Payment is already ${payment.status}.`);
  }
  if (payment.amount_poisha !== sms.amount_poisha) {
    return fail(res, 409, 'amount_mismatch', 'SMS amount does not match the payment amount.');
  }
  if (payment.sender_number && payment.sender_number !== sms.sender_number) {
    return fail(res, 409, 'sender_mismatch', 'SMS sender does not match the payment sender.');
  }
  const appRow = stmt.appById.get(payment.app_id);
  if (!appRow) return fail(res, 404, 'app_not_found', 'Payment app not found.');
  if (appRow.bkash_device_id !== sms.device_id && appRow.nagad_device_id !== sms.device_id) {
    return fail(res, 409, 'device_mismatch', 'This SMS device is not linked to the payment app.');
  }

  try {
    const result = db.transaction(() => {
      const lock = stmt.lockSmsPayment.run(payment.id, nowMs(), sms.id);
      if (lock.changes !== 1) throw new Error('SMS was matched concurrently');
      const completed = stmt.completePayment.run(
        sms.trx_id,
        sms.sender_number,
        sms.device_id,
        nowMs(),
        nowMs(),
        payment.id
      );
      if (completed.changes !== 1) throw new Error('payment changed state concurrently');
      enqueuePaymentEvent(payment.id, 'payment.succeeded');
      return true;
    }).immediate();

    if (!result) return fail(res, 409, 'match_failed', 'Could not match the SMS to the payment.');
  } catch (err) {
    return fail(res, 409, 'match_failed', String((err && err.message) || err));
  }

  log('info', 'sms manually matched', { sms_id: sms.id, payment_id: payment.id });
  res.json({
    ok: true,
    payment: serializePayment(stmt.paymentById.get(payment.id), baseUrl(req)),
  });
});

app.get('/api/admin/outbox', requireAdmin, (req, res) => {
  const limit = clampInt(req.query.limit, 1, 200, 50);
  const status = typeof req.query.status === 'string' && req.query.status ? req.query.status : null;
  if (status && !['pending', 'delivering', 'delivered', 'failed'].includes(status)) {
    return fail(res, 400, 'invalid_status', 'Invalid status filter.');
  }
  const rows = status ? stmt.outboxAllStatus.all(status, limit) : stmt.outboxAll.all(limit);
  res.json({
    object: 'list',
    data: rows.map((row) => ({
      id: row.id,
      event_id: row.event_id,
      app_id: row.app_id,
      app_name: row.app_name,
      payment_id: row.payment_id,
      event: row.event,
      status: row.status,
      attempts: row.attempts,
      next_attempt_at: iso(row.next_attempt_at),
      last_status_code: row.last_status_code,
      last_error: row.last_error,
      delivered_at: iso(row.delivered_at),
      created_at: iso(row.created_at),
    })),
    limit,
  });
});

app.post('/api/admin/outbox/:id/retry', requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return fail(res, 400, 'invalid_id', 'Invalid outbox id.');
  const row = stmt.outboxById.get(id);
  if (!row) return fail(res, 404, 'outbox_not_found', 'Outbox event not found.');
  const changed = stmt.outboxRetryManual.run(nowMs(), id);
  if (changed.changes !== 1) {
    return fail(res, 409, 'outbox_not_retryable', 'Only delivered or failed events can be retried.');
  }
  res.json({ ok: true, id, status: 'pending' });
});

app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const one = (sql, ...params) => db.prepare(sql).get(...params);
  const paymentCounts = db
    .prepare('SELECT status, COUNT(*) AS count FROM payments GROUP BY status')
    .all()
    .reduce((acc, row) => ({ ...acc, [row.status]: row.count }), {});
  const smsCounts = db
    .prepare(
      'SELECT CASE WHEN payment_id IS NULL THEN \'unmatched\' ELSE \'matched\' END AS state, COUNT(*) AS count FROM sms_payments GROUP BY state'
    )
    .all()
    .reduce((acc, row) => ({ ...acc, [row.state]: row.count }), {});
  const outboxCounts = db
    .prepare('SELECT status, COUNT(*) AS count FROM webhook_outbox GROUP BY status')
    .all()
    .reduce((acc, row) => ({ ...acc, [row.status]: row.count }), {});

  res.json({
    devices: one('SELECT COUNT(*) AS c FROM devices').c,
    apps: one('SELECT COUNT(*) AS c FROM apps').c,
    payments: {
      pending: paymentCounts.pending || 0,
      success: paymentCounts.success || 0,
      expired: paymentCounts.expired || 0,
      cancelled: paymentCounts.cancelled || 0,
      total: Object.values(paymentCounts).reduce((a, b) => a + b, 0),
    },
    sms: {
      matched: smsCounts.matched || 0,
      unmatched: smsCounts.unmatched || 0,
    },
    outbox: {
      pending: outboxCounts.pending || 0,
      delivering: outboxCounts.delivering || 0,
      delivered: outboxCounts.delivered || 0,
      failed: outboxCounts.failed || 0,
    },
  });
});

/* ------------------------------ error handling --------------------------- */

app.use((req, res) => {
  fail(res, 404, 'not_found', 'Route not found.');
});

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return fail(res, 400, 'invalid_json', 'Request body is not valid JSON.');
  }
  if (err && err.type === 'entity.too.large') {
    return fail(res, 413, 'payload_too_large', 'Request body is too large.');
  }
  log('error', 'unhandled request error', {
    method: req.method,
    path: req.path,
    error: String((err && err.message) || err),
    stack: err && err.stack ? String(err.stack).split('\n').slice(0, 4).join(' | ') : undefined,
  });
  if (res.headersSent) return next(err);
  return fail(res, 500, 'internal_error', 'Internal server error.');
});

/* -------------------------------------------------------------------------- *
 * Lifecycle
 * -------------------------------------------------------------------------- */

let httpServer = null;
let maintenanceTimerRef = null;

async function start(port = config.port) {
  if (httpServer) return httpServer;

  shuttingDown = false;
  stmt.outboxResetStale.run(nowMs());
  runMaintenance();
  scheduleOutbox(250);

  maintenanceTimerRef = setInterval(() => {
    try {
      runMaintenance();
    } catch (err) {
      log('error', 'maintenance tick failed', { error: String((err && err.message) || err) });
    }
  }, 30_000);
  maintenanceTimerRef.unref();

  await new Promise((resolve, reject) => {
    httpServer = http.createServer(app);
    httpServer.once('error', reject);
    httpServer.listen(port, config.host, () => {
      httpServer.off('error', reject);
      resolve();
    });
  });

  const address = httpServer.address();
  const actualPort = address && typeof address === 'object' ? address.port : port;

  log('info', `PayGate ${VERSION} listening`, {
    url: `http://${config.host}:${actualPort}`,
    env: config.env,
    database: config.dbPath,
    public_base_url: config.publicBaseUrl || '(derived from request)',
  });
  if (config.adminKeyGenerated) {
    log('warn', 'ADMIN_API_KEY was not set; generated a development key', { admin_key: config.adminKey });
  }

  // PM2 wait_ready support.
  if (typeof process.send === 'function') {
    try {
      process.send('ready');
    } catch {
      /* not running under PM2 */
    }
  }

  return httpServer;
}

async function stop() {
  shuttingDown = true;
  if (outboxTimer) {
    clearTimeout(outboxTimer);
    outboxTimer = null;
  }
  if (maintenanceTimerRef) {
    clearInterval(maintenanceTimerRef);
    maintenanceTimerRef = null;
  }

  if (httpServer) {
    const server = httpServer;
    httpServer = null;
    await new Promise((resolve) => server.close(() => resolve()));
  }

  try {
    db.pragma('wal_checkpoint(TRUNCATE)');
    db.close();
  } catch {
    /* already closed */
  }
}

if (require.main === module) {
  start().catch((err) => {
    log('error', 'failed to start', { error: String((err && err.stack) || err) });
    process.exit(1);
  });

  const shutdown = (signal) => {
    log('info', `${signal} received, shutting down`);
    const force = setTimeout(() => process.exit(1), 12_000);
    force.unref();
    stop()
      .then(() => process.exit(0))
      .catch(() => process.exit(1));
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  process.on('unhandledRejection', (reason) => {
    log('error', 'unhandled rejection', { error: String((reason && reason.stack) || reason) });
  });

  process.on('uncaughtException', (err) => {
    log('error', 'uncaught exception', { error: String((err && err.stack) || err) });
    stop()
      .then(() => process.exit(1))
      .catch(() => process.exit(1));
  });
}

module.exports = {
  app,
  db,
  config,
  start,
  stop,
  VERSION,
  __internals: {
    parseMoneyToPoisha,
    normalizePhone,
    parseAmountFromText,
    parseTrxIdFromText,
    parseSenderFromText,
    settleSms,
    drainOutbox,
  },
};

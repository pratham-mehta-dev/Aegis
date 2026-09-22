"use strict";

const path = require("node:path");
const fs = require("node:fs");
const { DatabaseSync } = require("node:sqlite");

const DATA_DIR = path.join(__dirname, "data");
fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new DatabaseSync(path.join(DATA_DIR, "auth.sqlite"));

db.exec("PRAGMA journal_mode = WAL;");
db.exec("PRAGMA foreign_keys = ON;");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  email_verified INTEGER NOT NULL DEFAULT 0,
  email_verify_token TEXT,
  email_verify_expires INTEGER,
  two_fa_enabled INTEGER NOT NULL DEFAULT 1,
  two_fa_method TEXT NOT NULL DEFAULT 'email',
  totp_secret TEXT,
  totp_pending_secret TEXT,
  password_reset_token TEXT,
  password_reset_expires INTEGER,
  failed_login_attempts INTEGER NOT NULL DEFAULT 0,
  lockout_until INTEGER,
  account_disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id, revoked);

CREATE TABLE IF NOT EXISTS otp_codes (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  purpose TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  consumed INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_otp_lookup ON otp_codes(user_id, purpose, consumed, created_at);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  email TEXT,
  event TEXT NOT NULL,
  ip TEXT,
  detail TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit_log(created_at);

CREATE TABLE IF NOT EXISTS alerts (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  layer TEXT NOT NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0,
  malicious INTEGER NOT NULL DEFAULT 0,
  source_ip TEXT,
  endpoint TEXT,
  method TEXT,
  payload TEXT,
  model TEXT,
  simulated INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'new',
  reviewed_by TEXT,
  reviewed_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_ip);

CREATE TABLE IF NOT EXISTS blocked_ips (
  id TEXT PRIMARY KEY,
  ip TEXT NOT NULL UNIQUE,
  reason TEXT,
  layer TEXT,
  blocked_by TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_blocked_active ON blocked_ips(ip, active);
`);

// Periodically purge expired OTP codes and refresh tokens (keeps the DB small).
function purgeExpired() {
  const now = Date.now();
  try {
    db.prepare("DELETE FROM otp_codes WHERE expires_at < ?").run(now);
    db.prepare("DELETE FROM refresh_tokens WHERE expires_at < ?").run(now);
  } catch (err) {
    console.error("[db] purgeExpired failed:", err.message);
  }
}
setInterval(purgeExpired, 60 * 60 * 1000).unref();
purgeExpired();

module.exports = db;

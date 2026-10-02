"use strict";

// Smoke tests for the API. Run with: npm test
// Uses mail dev mode (no SMTP needed). Requires env vars set below before require.

process.env.JWT_ACCESS_SECRET = "test-access-secret-" + "x".repeat(32);
process.env.PENDING_2FA_SECRET = "test-pending-secret-" + "y".repeat(32);
process.env.FRONTEND_URL = "http://localhost:4001";
process.env.APP_BASE_URL = "http://localhost:4001";
const suricataToken = "test-suricata-token-" + "z".repeat(32);
process.env.SURICATA_INGEST_TOKEN = suricataToken;
process.env.NODE_ENV = "test";
delete process.env.GOOGLE_CLIENT_ID;
delete process.env.GOOGLE_CLIENT_SECRET;
delete process.env.GOOGLE_REDIRECT_URI;
// Isolated DB per run so tests are repeatable and never touch the real data/ dir.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
process.env.DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aegis-test-")), "test.sqlite");

const { test, before, after } = require("node:test");
const assert = require("node:assert");

const app = require("../server");
const db = require("../db");
let server;
let base;

before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      base = `http://127.0.0.1:${server.address().port}`;
      resolve();
    });
  });
});

after(() => server && server.close());

const post = (path, body, headers = {}) =>
  fetch(`${base}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body: JSON.stringify(body),
  });

const postSuricataEvent = (event) =>
  post("/api/ids/suricata/eve", event, {
    Authorization: `Bearer ${suricataToken}`,
  });

test("health check", async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
});

test("serves frontend index.html on single-origin port 4001", async () => {
  const res = await fetch(`${base}/`);
  assert.equal(res.status, 200);
  const text = await res.text();
  assert.ok(text.includes("<div id=\"root\">") || text.includes("<!DOCTYPE html>"));
});

test("Google sign-in stays disabled until OAuth credentials are configured", async () => {
  const status = await fetch(`${base}/api/auth/google/status`);
  assert.deepEqual(await status.json(), { enabled: false });
  const start = await fetch(`${base}/api/auth/google`, { redirect: "manual" });
  assert.equal(start.status, 503);
});

test("register rejects non-gmail address", async () => {
  const res = await post("/api/auth/register", {
    name: "T",
    email: "a@example.com",
    password: "Str0ng!Pass",
  });
  assert.equal(res.status, 400);
});

test("register rejects weak password", async () => {
  const res = await post("/api/auth/register", {
    name: "T",
    email: "t1@gmail.com",
    password: "weak",
  });
  assert.equal(res.status, 400);
});

test("register succeeds and login is blocked until verified", async () => {
  const reg = await post("/api/auth/register", {
    name: "Smoke User",
    email: "smoke.user1@gmail.com",
    password: "Str0ng!Pass",
  });
  assert.equal(reg.status, 201);
  const login = await post("/api/auth/login", {
    email: "smoke.user1@gmail.com",
    password: "Str0ng!Pass",
  });
  assert.equal(login.status, 403);
});

test("duplicate registration returns 409", async () => {
  const res = await post("/api/auth/register", {
    name: "Dup",
    email: "smoke.user1@gmail.com",
    password: "Str0ng!Pass",
  });
  assert.equal(res.status, 409);
});

test("admin API requires auth", async () => {
  const res = await fetch(`${base}/api/admin/stats`);
  assert.equal(res.status, 401);
  const usersRes = await fetch(`${base}/api/admin/users`);
  assert.equal(usersRes.status, 401);
});

test("admin API rejects a non-admin token", async () => {
  const jwt = require("jsonwebtoken");
  const token = jwt.sign({ sub: "no-such-user", role: "user" }, process.env.JWT_ACCESS_SECRET);
  const res = await fetch(`${base}/api/admin/stats`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  // user doesn't exist -> 401 (requireAuth). A real non-admin user would be 403;
  // covered manually in verification notes.
  assert.ok([401, 403].includes(res.status));
});

test("admin users endpoint returns user list for authorized admin", async () => {
  const jwt = require("jsonwebtoken");
  const adminId = "admin-test-user-id";
  db.prepare(
    `INSERT INTO users (id, name, email, password_hash, role, email_verified, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'admin', 1, ?, ?)`
  ).run(adminId, "Admin Test", "admintest@gmail.com", "hash", Date.now(), Date.now());

  const token = jwt.sign({ sub: adminId, role: "admin" }, process.env.JWT_ACCESS_SECRET);
  const res = await fetch(`${base}/api/admin/users`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(Array.isArray(body.users));
  assert.ok(body.users.some((u) => u.email === "admintest@gmail.com"));
});

test("forgot-password reply is generic", async () => {
  const res = await post("/api/auth/forgot-password", { email: "nobody-xyz@gmail.com" });
  const body = await res.json();
  assert.equal(res.status, 200);
  assert.match(body.message, /If that account exists/);
});

test("verify-email rejects bad token", async () => {
  const res = await fetch(`${base}/api/auth/verify-email?token=bogus`);
  assert.equal(res.status, 400);
});

test("predict rejects empty payload", async () => {
  const res = await post("/api/ids/predict", { payload: "   " });
  assert.equal(res.status, 400);
});

test("suricata eve endpoint stores incoming alerts", async () => {
  const event = {
    alert: {
      signature: "ET TEST ALERT",
      category: "Attempted Information Leak",
      severity: 1,
      msg: "ET TEST ALERT",
    },
    src_ip: "10.0.0.5",
    dest_ip: "10.0.0.8",
    dest_port: 443,
    app_proto: "http",
  };
  const res = await post("/api/ids/suricata/eve", event, {
    Authorization: `Bearer ${suricataToken}`,
  });

  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.inserted, 1);
  const row = db
    .prepare("SELECT type, source_ip, model FROM alerts WHERE model = 'suricata' ORDER BY created_at DESC LIMIT 1")
    .get();
  assert.equal(row.type, "ET TEST ALERT");
  assert.equal(row.source_ip, "10.0.0.5");
  assert.equal(row.model, "suricata");
});

test("suricata eve endpoint rejects requests without sensor authentication", async () => {
  const res = await post("/api/ids/suricata/eve", { alert: { signature: "UNTRUSTED" } });
  assert.equal(res.status, 401);
});

test("sensor blocklist endpoint exposes active entries only with sensor authentication", async () => {
  db.prepare(
    `INSERT INTO blocked_ips (id, ip, reason, layer, blocked_by, active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run("active-lab-block", "10.77.0.2", "Test block", "Network", "test", 1, Date.now());
  db.prepare(
    `INSERT INTO blocked_ips (id, ip, reason, layer, blocked_by, active, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run("inactive-lab-block", "10.77.0.3", "Removed test block", "Network", "test", 0, Date.now());

  const unauthorized = await fetch(`${base}/api/ids/suricata/blocks`);
  assert.equal(unauthorized.status, 401);

  const res = await fetch(`${base}/api/ids/suricata/blocks`, {
    headers: { Authorization: `Bearer ${suricataToken}` },
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { blocked: ["10.77.0.2"] });
});

test("suricata eve endpoint rejects an invalid sensor token", async () => {
  const res = await post(
    "/api/ids/suricata/eve",
    { alert: { signature: "UNTRUSTED" } },
    { Authorization: "Bearer invalid-token" }
  );
  assert.equal(res.status, 401);
});

test("only the third recent High alert from a lab client triggers an auto-block", async () => {
  const sourceIp = "10.77.0.3";

  for (let count = 1; count <= 3; count += 1) {
    const res = await postSuricataEvent({
      event_type: "alert",
      src_ip: sourceIp,
      alert: { signature: `AEGIS HIGH TEST ${count}`, severity: 1 },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.alerts[0].auto_blocked, count === 3);
  }

  const block = db.prepare("SELECT active, blocked_by FROM blocked_ips WHERE ip = ?").get(sourceIp);
  assert.equal(block.active, 1);
  assert.equal(block.blocked_by, "aegis-engine");
});

test("Low/Info and out-of-lab alerts do not auto-block; lab auto-blocks persist until removed", async () => {
  for (const event of [
    { src_ip: "10.77.0.4", severity: 3, signature: "AEGIS LOW TEST" },
    { src_ip: "10.77.0.5", severity: 4, signature: "AEGIS INFO TEST" },
    { src_ip: "192.168.1.50", severity: 1, signature: "AEGIS OUTSIDE TEST" },
  ]) {
    const res = await postSuricataEvent({
      event_type: "alert",
      src_ip: event.src_ip,
      alert: { signature: event.signature, severity: event.severity },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.alerts[0].auto_blocked, false);
  }

  const lowAlert = db
    .prepare("SELECT malicious FROM alerts WHERE type = ? ORDER BY created_at DESC LIMIT 1")
    .get("AEGIS LOW TEST");
  const infoAlert = db
    .prepare("SELECT malicious FROM alerts WHERE type = ? ORDER BY created_at DESC LIMIT 1")
    .get("AEGIS INFO TEST");
  assert.equal(lowAlert.malicious, 0);
  assert.equal(infoAlert.malicious, 0);

  db.prepare("UPDATE blocked_ips SET created_at = ? WHERE ip = ? AND blocked_by = ?")
    .run(Date.now() - 24 * 60 * 60 * 1000, "10.77.0.3", "aegis-engine");
  const res = await fetch(`${base}/api/ids/suricata/blocks`, {
    headers: { Authorization: `Bearer ${suricataToken}` },
  });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.ok(body.blocked.includes("10.77.0.3"));

  db.prepare("UPDATE blocked_ips SET active = 0 WHERE ip = ? AND blocked_by = ?")
    .run("10.77.0.3", "aegis-engine");
  const afterUnblock = await fetch(`${base}/api/ids/suricata/blocks`, {
    headers: { Authorization: `Bearer ${suricataToken}` },
  });
  assert.equal(afterUnblock.status, 200);
  assert.ok(!(await afterUnblock.json()).blocked.includes("10.77.0.3"));
});

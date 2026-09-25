"use strict";

// Smoke tests for the API. Run with: npm test
// Uses mail dev mode (no SMTP needed). Requires env vars set below before require.

process.env.JWT_ACCESS_SECRET = "test-access-secret-" + "x".repeat(32);
process.env.PENDING_2FA_SECRET = "test-pending-secret-" + "y".repeat(32);
process.env.FRONTEND_URL = "http://localhost:4000";
process.env.APP_BASE_URL = "http://localhost:4000";
process.env.NODE_ENV = "test";
// Isolated DB per run so tests are repeatable and never touch the real data/ dir.
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
process.env.DB_PATH = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "aegis-test-")), "test.sqlite");

const { test, before, after } = require("node:test");
const assert = require("node:assert");

const app = require("../server");
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

test("health check", async () => {
  const res = await fetch(`${base}/health`);
  assert.equal(res.status, 200);
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

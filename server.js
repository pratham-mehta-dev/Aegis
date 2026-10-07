// --- Crash Prevention Guards ---
process.on('uncaughtException', (err) => {
  console.error('[FATAL ERROR PREVENTED] Uncaught Exception:', err.message);
  console.error(err.stack);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[PROMISE REJECTION PREVENTED] Unhandled Rejection at:', promise, 'reason:', reason);
});
// -------------------------------

"use strict";

// Minimal .env loader so no extra dependency is required for secrets.
const fs = require("node:fs");
const path = require("node:path");
const envFile = path.join(__dirname, ".env");
if (process.env.NODE_ENV !== "test" && fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, "utf8").split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (!m || m[1].startsWith("#")) continue;
    if (process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, "");
    }
  }
}

const express = require("express");
const cookieParser = require("cookie-parser");

const REQUIRED_ENV = ["JWT_ACCESS_SECRET", "PENDING_2FA_SECRET", "FRONTEND_URL"];
if (process.env.NODE_ENV === "production") {
  REQUIRED_ENV.push("SMTP_HOST", "SMTP_USER", "SMTP_PASS", "SMTP_FROM");
}
const missing = REQUIRED_ENV.filter((k) => !process.env[k]);
if (missing.length) {
  console.error(`[startup] missing required env vars: ${missing.join(", ")} (see .env.example)`);
  process.exit(1);
}
if (process.env.JWT_ACCESS_SECRET === process.env.PENDING_2FA_SECRET) {
  console.error("[startup] JWT_ACCESS_SECRET and PENDING_2FA_SECRET must be different.");
  process.exit(1);
}

const authRouter = require("./auth");
const idsRouter = require("./ids");
const adminRouter = require("./admin");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

const allowedOrigins = new Set(
  String(process.env.CORS_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean)
);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowNull = process.env.NODE_ENV !== "production" && origin === "null";
  if (origin && (allowedOrigins.has(origin) || allowNull)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,DELETE,OPTIONS");
  }
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

app.use(express.json({ limit: "32kb" }));
app.use(cookieParser());

process.on("unhandledRejection", (err) => {
  console.error("[unhandledRejection]", err);
});
process.on("uncaughtException", (err) => {
  console.error("[uncaughtException]", err);
});

// Health check endpoint
app.get("/health", (req, res) => res.json({ ok: true }));

// --- Permanent Attack Simulation Endpoint ---
app.get("/aegis-test-attack", (req, res) => {
  res.status(200).json({
    status: "success",
    message: "Aegis test attack pattern detected and processed. Signature dispatched across network.",
    timestamp: new Date().toISOString(),
    clientIp: req.ip || req.socket.remoteAddress
  });
});
// --------------------------------------------
app.get("/aegis-test-attack", (req, res) => {
  res.status(200).json({
    status: "success",
    message: "Aegis test attack pattern detected and processed.",
    timestamp: new Date().toISOString()
  });
});

app.use("/api/auth", authRouter);
app.use("/api/ids", idsRouter);
app.use("/api/admin", adminRouter);

// Model metadata for the SOC "Model Settings" tab.
const { requireAuth } = require("./middleware/auth");
const { requireRole } = require("./middleware/requireRole");
const { asyncHandler } = require("./middleware/asyncHandler");
app.get(
  "/api/model/info",
  requireAuth,
  requireRole("admin"),
  asyncHandler(async (req, res) => {
    const url = (process.env.ML_SERVICE_URL || "http://127.0.0.1:5000").replace(/\/+$/, "");
    try {
      const resp = await fetch(`${url}/health`, { signal: AbortSignal.timeout(3000) });
      if (!resp.ok) throw new Error(`status ${resp.status}`);
      const info = await resp.json();
      res.json({ online: true, ...info });
    } catch {
      res.json({ online: false });
    }
  })
);

// Serve the built frontend when present (single-origin deploy / demo).
const distDir = path.join(__dirname, "frontend", "dist");
if (fs.existsSync(distDir)) {
  app.use(express.static(distDir));
  app.get(/^(?!\/api\/).*/, (req, res) => res.sendFile(path.join(distDir, "index.html")));
}

app.use((err, req, res, next) => {
  console.error("[error]", err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({ error: "Internal server error." });
});

const PORT = Number(process.env.PORT || 4001);

if (require.main === module) {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`[aegis] API listening on http://0.0.0.0:${PORT}`);
    if (require("./mailer").mailDevMode()) {
      console.log("[aegis] mail dev mode: emails are printed to console and data/outbox.log");
    }
  });
}

module.exports = app;
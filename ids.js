"use strict";

const express = require("express");
const { v4: uuidv4 } = require("uuid");

const db = require("./db");
const { idsLimiter } = require("./middleware/rateLimiter");
const { asyncHandler } = require("./middleware/asyncHandler");

const router = express.Router();

const ML_URL = (process.env.ML_SERVICE_URL || "http://127.0.0.1:5000").replace(/\/+$/, "");
const MAX_PAYLOAD = 4096;

const isBlocked = (ip) =>
  Boolean(db.prepare("SELECT 1 FROM blocked_ips WHERE ip = ? AND active = 1").get(ip));

const recordAlert = (req, verdict, { simulated = false, payload = null } = {}) => {
  try {
    const id = `A-${uuidv4().slice(0, 8).toUpperCase()}`;
    db.prepare(
      `INSERT INTO alerts (id, created_at, layer, type, severity, confidence, malicious,
        source_ip, endpoint, method, payload, model, simulated, status)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,'new')`
    ).run(
      id,
      Date.now(),
      verdict.layer || "Application",
      verdict.type,
      verdict.severity || "Low",
      Number(verdict.confidence) || 0,
      verdict.malicious ? 1 : 0,
      req.ip || null,
      req.body?.endpoint || req.originalUrl || null,
      req.method || null,
      payload === null ? null : String(payload).slice(0, 2000),
      verdict.model || null,
      simulated ? 1 : 0
    );
    return id;
  } catch (err) {
    console.error("[ids] alert persist failed:", err.message);
    return null;
  }
};

// POST /api/ids/predict { payload, endpoint? }
// Public (the storefront must call it before login) but rate-limited.
router.post(
  "/predict",
  idsLimiter,
  asyncHandler(async (req, res) => {
    const payload = String(req.body?.payload ?? "");
    if (!payload.trim()) return res.status(400).json({ error: "payload is required." });
    if (payload.length > MAX_PAYLOAD) {
      return res.status(400).json({ error: "payload too large." });
    }

    if (isBlocked(req.ip)) {
      recordAlert(req, { type: "Blocked Source", severity: "High", malicious: true, layer: "Application" }, { payload });
      return res.status(403).json({ error: "This source is blocked.", blocked: true });
    }

    let verdict;
    try {
      const resp = await fetch(`${ML_URL}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ payload }),
        signal: AbortSignal.timeout(5000),
      });
      if (!resp.ok) throw new Error(`ML returned ${resp.status}`);
      verdict = await resp.json();
    } catch (err) {
      console.error("[ids] ML call failed:", err.message);
      return res.status(503).json({ error: "Detection service unavailable." });
    }

    const alertId = recordAlert(req, verdict, { payload });

    // Auto-block the source IP on malicious application-layer verdicts.
    if (verdict.malicious && req.ip && !isBlocked(req.ip)) {
      try {
        db.prepare(
          `INSERT INTO blocked_ips (id, ip, reason, layer, blocked_by, active, created_at)
           VALUES (?,?,?,?,?,1,?)
           ON CONFLICT(ip) DO UPDATE SET active = 1, reason = excluded.reason`
        ).run(uuidv4(), req.ip, `Auto-block: ${verdict.type}`, verdict.layer || "Application", "aegis-engine", Date.now());
      } catch (err) {
        console.error("[ids] auto-block failed:", err.message);
      }
    }

    return res.json({ ...verdict, alertId });
  })
);

// POST /api/ids/simulate { type } — persists a clearly-labelled simulated alert
// for the Attack Simulator's network-layer presets (there is no packet capture).
const SIMULATED_TYPES = {
  "Port Scan": { severity: "High", detail: "nmap -sS", layer: "Network" },
  "DoS Flood": { severity: "Critical", detail: "hping3 --flood", layer: "Network" },
  "Brute Force": { severity: "High", detail: "hydra ssh", layer: "Network" },
};

router.post("/simulate", idsLimiter, (req, res) => {
  const type = String(req.body?.type || "");
  const preset = SIMULATED_TYPES[type];
  if (!preset) return res.status(400).json({ error: "Unknown simulated attack type." });
  if (isBlocked(req.ip)) {
    return res.status(403).json({ error: "This source is blocked.", blocked: true });
  }
  const alertId = recordAlert(
    req,
    {
      type,
      severity: preset.severity,
      malicious: true,
      confidence: 0.99,
      layer: preset.layer,
      model: "simulated",
    },
    { simulated: true, payload: `simulated: ${preset.detail}` }
  );
  return res.json({
    malicious: true,
    type,
    confidence: 0.99,
    severity: preset.severity,
    layer: preset.layer,
    model: "simulated",
    simulated: true,
    alertId,
  });
});

module.exports = router;

"use strict";

const { timingSafeEqual } = require("node:crypto");
const express = require("express");
const { v4: uuidv4 } = require("uuid");

const db = require("./db");
const { idsLimiter } = require("./middleware/rateLimiter");
const { asyncHandler } = require("./middleware/asyncHandler");
const { requireAuth } = require("./middleware/auth");
const { requireRole } = require("./middleware/requireRole");

const router = express.Router();

const ML_URL = (process.env.ML_SERVICE_URL || "http://127.0.0.1:5000").replace(/\/+$/, "");
const SURICATA_INGEST_TOKEN = process.env.SURICATA_INGEST_TOKEN || "";
const MAX_PAYLOAD = 4096;
const AUTO_BLOCK_WINDOW_MS = 5 * 60 * 1000;
const AUTO_BLOCK_THRESHOLD = 3;

const requireSuricataToken = (req, res, next) => {
  if (!SURICATA_INGEST_TOKEN) {
    return res.status(503).json({ error: "Suricata ingestion is not configured." });
  }

  const match = (req.get("authorization") || "").match(/^Bearer\s+(.+)$/i);
  if (!match) return res.status(401).json({ error: "Sensor authentication required." });

  const provided = Buffer.from(match[1]);
  const expected = Buffer.from(SURICATA_INGEST_TOKEN);
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return res.status(401).json({ error: "Invalid sensor credentials." });
  }
  next();
};

const isBlocked = (ip) =>
  Boolean(db.prepare("SELECT 1 FROM blocked_ips WHERE ip = ? AND active = 1").get(ip));

const isLabClientIp = (ip) => {
  if (typeof ip !== "string") return false;
  const octets = ip.split(".").map(Number);
  return (
    octets.length === 4 &&
    octets.every((octet) => Number.isInteger(octet) && octet >= 0 && octet <= 255) &&
    octets[0] === 10 &&
    octets[1] === 77 &&
    octets[2] === 0 &&
    octets[3] > 1 &&
    octets[3] < 255
  );
};

const maybeAutoBlockLabClient = (sourceIp, severity, signature) => {
  if (severity !== 1 || !isLabClientIp(sourceIp) || isBlocked(sourceIp)) return false;

  const now = Date.now();
  const recentHighAlerts = db
    .prepare(
      `SELECT COUNT(*) AS count FROM alerts
       WHERE model = 'suricata' AND source_ip = ? AND severity = 'High' AND created_at >= ?`
    )
    .get(sourceIp, now - AUTO_BLOCK_WINDOW_MS).count;
  if (recentHighAlerts < AUTO_BLOCK_THRESHOLD) return false;

  db.prepare(
    `INSERT INTO blocked_ips (id, ip, reason, layer, blocked_by, active, created_at)
     VALUES (?,?,?,?,?,1,?)
     ON CONFLICT(ip) DO UPDATE SET
       active = 1, reason = excluded.reason, layer = excluded.layer,
       blocked_by = excluded.blocked_by, created_at = excluded.created_at`
  ).run(
    uuidv4(),
    sourceIp,
    `Automatic: ${signature}`.slice(0, 300),
    "Network",
    "aegis-engine",
    now
  );
  return true;
};

router.get("/suricata/blocks", requireSuricataToken, idsLimiter, (req, res) => {
  const blocked = db
    .prepare("SELECT ip FROM blocked_ips WHERE active = 1 ORDER BY ip")
    .all()
    .map((row) => row.ip);
  res.json({ blocked });
});

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

// POST /api/ids/suricata/eve { ... } - ingest real EVE JSON events from Suricata.
router.post(
  "/suricata/eve",
  requireSuricataToken,
  idsLimiter,
  asyncHandler(async (req, res) => {
    const raw = req.body;
    const events = Array.isArray(raw) ? raw : [raw];
    const inserted = [];

    for (const event of events) {
      if (!event || !event.alert) continue;

      const alert = event.alert;
      const severityNumber = Number(alert.severity);
      const severityMap = { 1: "High", 2: "Medium", 3: "Low", 4: "Info" };
      const severity = severityMap[severityNumber] || "Medium";
      const id = `A-${uuidv4().slice(0, 8).toUpperCase()}`;
      const type = String(alert.signature || alert.msg || "Suricata alert");
      const endpoint = event.dest_ip ? `${event.dest_ip}:${event.dest_port || 0}` : null;

      db.prepare(
        `INSERT INTO alerts (id, created_at, layer, type, severity, confidence, malicious,
          source_ip, endpoint, method, payload, model, simulated, status)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?, 'new')`
      ).run(
        id,
        Date.now(),
        "Network",
        type,
        severity,
        Number(alert.severity || 0) / 10 || 0.5,
        [1, 2].includes(severityNumber) ? 1 : 0,
        event.src_ip || null,
        endpoint,
        event.app_proto || "tcp",
        JSON.stringify(event),
        "suricata",
        0
      );

      const autoBlocked = maybeAutoBlockLabClient(event.src_ip, severityNumber, type);
      inserted.push({ id, type, source_ip: event.src_ip || null, auto_blocked: autoBlocked });
    }

    return res.json({ ok: true, inserted: inserted.length, alerts: inserted });
  })
);

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

router.post("/simulate", idsLimiter, requireAuth, requireRole("admin"), (req, res) => {
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

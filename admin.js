"use strict";

const express = require("express");
const { v4: uuidv4 } = require("uuid");

const db = require("./db");
const { requireAuth } = require("./middleware/auth");
const { requireRole } = require("./middleware/requireRole");
const { audit } = require("./utils/audit");

const router = express.Router();
router.use(requireAuth, requireRole("admin"));

const IP_RE = /^(?:\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$/;

// ---------- alerts ----------

// GET /api/admin/alerts?layer=&severity=&status=&q=&page=&limit=
router.get("/alerts", (req, res) => {
  const { layer, severity, status, q } = req.query;
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
  const where = [];
  const params = [];
  if (layer && ["Application", "Network"].includes(layer)) {
    where.push("layer = ?");
    params.push(layer);
  }
  if (severity && ["Critical", "High", "Medium", "Low"].includes(severity)) {
    where.push("severity = ?");
    params.push(severity);
  }
  if (status && ["new", "confirmed", "false_positive"].includes(status)) {
    where.push("status = ?");
    params.push(status);
  }
  if (q) {
    where.push("source_ip LIKE ?");
    params.push(`%${String(q).slice(0, 64)}%`);
  }
  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";
  const total = db.prepare(`SELECT COUNT(*) AS n FROM alerts ${whereSql}`).get(...params).n;
  const rows = db
    .prepare(
      `SELECT id, created_at, layer, type, severity, confidence, malicious, source_ip,
              endpoint, method, model, simulated, status
       FROM alerts ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    )
    .all(...params, limit, (page - 1) * limit);
  res.json({ alerts: rows, total, page, limit });
});

router.get("/alerts/export.csv", (req, res) => {
  const rows = db
    .prepare(
      `SELECT id, created_at, layer, type, severity, confidence, source_ip, endpoint, status
       FROM alerts ORDER BY created_at DESC LIMIT 10000`
    )
    .all();
  const esc = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
  const header = "id,created_at,layer,type,severity,confidence,source_ip,endpoint,status\n";
  const body = rows
    .map((r) =>
      [
        r.id,
        new Date(r.created_at).toISOString(),
        r.layer,
        r.type,
        r.severity,
        r.confidence,
        r.source_ip,
        r.endpoint,
        r.status,
      ]
        .map(esc)
        .join(",")
    )
    .join("\n");
  res.setHeader("Content-Type", "text/csv");
  res.setHeader("Content-Disposition", "attachment; filename=aegis-alerts.csv");
  res.send(header + body + "\n");
});

router.get("/alerts/:id", (req, res) => {
  const alert = db.prepare("SELECT * FROM alerts WHERE id = ?").get(req.params.id);
  if (!alert) return res.status(404).json({ error: "Alert not found." });
  res.json({ alert });
});

// PATCH /api/admin/alerts/:id { action: "confirm" | "false_positive" }
router.patch("/alerts/:id", (req, res) => {
  const action = String(req.body?.action || "");
  const status =
    action === "confirm" ? "confirmed" : action === "false_positive" ? "false_positive" : null;
  if (!status) return res.status(400).json({ error: "action must be confirm or false_positive." });
  const result = db
    .prepare("UPDATE alerts SET status = ?, reviewed_by = ?, reviewed_at = ? WHERE id = ?")
    .run(status, req.user.id, Date.now(), req.params.id);
  if (!result.changes) return res.status(404).json({ error: "Alert not found." });
  audit(req, { userId: req.user.id, email: req.user.email, event: "alert_review", detail: `${req.params.id} -> ${status}` });
  res.json({ message: "Alert updated.", status });
});

// ---------- blocklist ----------

router.get("/blocklist", (req, res) => {
  const rows = db
    .prepare(
      `SELECT b.id, b.ip, b.reason, b.layer, b.blocked_by, b.created_at,
              (SELECT COUNT(*) FROM alerts a WHERE a.source_ip = b.ip) AS alert_count
       FROM blocked_ips b WHERE b.active = 1 ORDER BY b.created_at DESC`
    )
    .all();
  res.json({ blocked: rows });
});

router.post("/blocklist", (req, res) => {
  const ip = String(req.body?.ip || "").trim();
  const reason = String(req.body?.reason || "").slice(0, 300);
  if (!IP_RE.test(ip) || ip.length > 64) {
    return res.status(400).json({ error: "A valid IP address is required." });
  }
  db.prepare(
    `INSERT INTO blocked_ips (id, ip, reason, layer, blocked_by, active, created_at)
     VALUES (?,?,?,?,?,1,?)
     ON CONFLICT(ip) DO UPDATE SET active = 1, reason = excluded.reason, blocked_by = excluded.blocked_by`
  ).run(uuidv4(), ip, reason || "Manual block", "Manual", req.user.email, Date.now());
  audit(req, { userId: req.user.id, email: req.user.email, event: "ip_blocked", detail: `${ip} (${reason || "Manual block"})` });
  res.status(201).json({ message: `${ip} blocked.` });
});

router.delete("/blocklist/:ip", (req, res) => {
  const result = db
    .prepare("UPDATE blocked_ips SET active = 0 WHERE ip = ? AND active = 1")
    .run(req.params.ip);
  if (!result.changes) return res.status(404).json({ error: "IP is not blocked." });
  audit(req, { userId: req.user.id, email: req.user.email, event: "ip_unblocked", detail: req.params.ip });
  res.json({ message: `${req.params.ip} unblocked.` });
});

// ---------- stats ----------

router.get("/stats", (req, res) => {
  const since = Date.now() - 24 * 60 * 60 * 1000;
  const total = db.prepare("SELECT COUNT(*) AS n FROM alerts WHERE created_at >= ?").get(since).n;
  const critical = db
    .prepare("SELECT COUNT(*) AS n FROM alerts WHERE severity = 'Critical' AND created_at >= ?")
    .get(since).n;
  const blocked = db.prepare("SELECT COUNT(*) AS n FROM blocked_ips WHERE active = 1").get().n;
  const byType = db
    .prepare(
      "SELECT type, COUNT(*) AS n FROM alerts WHERE type != 'Benign' AND created_at >= ? GROUP BY type"
    )
    .all(since);
  const feed = db
    .prepare(
      `SELECT id, created_at, layer, type, severity, source_ip, status, simulated
       FROM alerts ORDER BY created_at DESC LIMIT 30`
    )
    .all();
  res.json({
    total24h: total,
    critical24h: critical,
    blockedSources: blocked,
    byType,
    feed,
    model: "Hybrid ML + Suricata",
  });
});

// ---------- audit viewer ----------

router.get("/audit", (req, res) => {
  const rows = db
    .prepare("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200")
    .all();
  res.json({ audit: rows });
});

// ---------- users list ----------

router.get("/users", (req, res) => {
  const rows = db
    .prepare(
      `SELECT id, email, name, role, email_verified, two_fa_method,
              lockout_until, failed_login_attempts, account_disabled, created_at,
              (SELECT COUNT(*) FROM audit_log a WHERE a.user_id = users.id OR a.email = users.email) AS audit_count
       FROM users ORDER BY created_at DESC`
    )
    .all();
  res.json({ users: rows });
});

module.exports = router;

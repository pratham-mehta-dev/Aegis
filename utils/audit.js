"use strict";

const { v4: uuidv4 } = require("uuid");
const db = require("../db");

// Write a security-relevant event. Never throws — audit must not break requests.
const audit = (req, { userId = null, email = null, event, detail = null }) => {
  try {
    db.prepare(
      "INSERT INTO audit_log (id, user_id, email, event, ip, detail, created_at) VALUES (?,?,?,?,?,?,?)"
    ).run(uuidv4(), userId, email, event, req.ip || null, detail, Date.now());
  } catch (err) {
    console.error("[audit] write failed:", err.message);
  }
};

module.exports = { audit };

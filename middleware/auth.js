"use strict";

const jwt = require("jsonwebtoken");
const db = require("../db");

// Verifies the Bearer access token and re-loads the user so that
// account_disabled / role changes apply immediately.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "Authentication required." });
  }
  try {
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(payload.sub);
    if (!user || user.account_disabled) {
      return res.status(401).json({ error: "Authentication required." });
    }
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: "Session expired. Please sign in again." });
  }
}

module.exports = { requireAuth };

"use strict";

// Server-side authorization. Always used after requireAuth (which loads req.user).
const requireRole = (...roles) => (req, res, next) => {
  if (!req.user || !roles.includes(req.user.role)) {
    return res.status(403).json({ error: "Not authorized for this resource." });
  }
  next();
};

module.exports = { requireRole };

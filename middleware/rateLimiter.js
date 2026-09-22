"use strict";

// Simple fixed-window, per-IP in-memory rate limiter (single-process demo scope).
const buckets = new Map();

function makeLimiter({ windowMs, max, message }) {
  return (req, res, next) => {
    const key = `${req.path}|${req.ip}`;
    const now = Date.now();
    let bucket = buckets.get(key);
    if (!bucket || now - bucket.start > windowMs) {
      bucket = { start: now, count: 0 };
      buckets.set(key, bucket);
    }
    bucket.count += 1;
    if (bucket.count > max) {
      return res.status(429).json({ error: message || "Too many requests. Try again later." });
    }
    next();
  };
}

// Occasional sweep so the map does not grow unbounded.
setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    if (now - bucket.start > 60 * 60 * 1000) buckets.delete(key);
  }
}, 15 * 60 * 1000).unref();

const loginLimiter = makeLimiter({ windowMs: 15 * 60 * 1000, max: 10 });
const otpLimiter = makeLimiter({ windowMs: 10 * 60 * 1000, max: 10 });
const forgotLimiter = makeLimiter({ windowMs: 15 * 60 * 1000, max: 5 });
const registerLimiter = makeLimiter({ windowMs: 60 * 60 * 1000, max: 5 });
const idsLimiter = makeLimiter({ windowMs: 60 * 1000, max: 60 });

module.exports = { loginLimiter, otpLimiter, forgotLimiter, registerLimiter, idsLimiter };

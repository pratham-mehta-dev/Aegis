"use strict";

const crypto = require("node:crypto");

const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString("hex");

const randomOtp = () => String(crypto.randomInt(0, 1000000)).padStart(6, "0");

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");

// Constant-time comparison of two hex digests.
const safeEqual = (a, b) => {
  const ba = Buffer.from(String(a || ""));
  const bb = Buffer.from(String(b || ""));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
};

module.exports = { randomToken, randomOtp, sha256, safeEqual };

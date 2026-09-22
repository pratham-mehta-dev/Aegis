"use strict";

const { authenticator } = require("otplib");

authenticator.options = { window: 1, step: 30 };

const issuer = () => process.env.TOTP_ISSUER || "Aegis";

const generateSecret = () => authenticator.generateSecret();

const verifyTotp = (token, secret) => {
  try {
    return authenticator.verify({ token, secret });
  } catch {
    return false;
  }
};

// otpauth:// URL; the frontend renders it into a QR code image.
const keyUri = (email, secret) => authenticator.keyuri(email, issuer(), secret);

module.exports = { generateSecret, verifyTotp, keyUri };

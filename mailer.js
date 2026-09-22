"use strict";

const fs = require("node:fs");
const path = require("node:path");
const nodemailer = require("nodemailer");

const OUTBOX = path.join(__dirname, "data", "outbox.log");

const escapeHtml = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const smtpConfigured = () => Boolean(process.env.SMTP_HOST);

const mailDevMode = () => !smtpConfigured() && process.env.NODE_ENV !== "production";

function buildTransport() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
      : undefined,
  });
}

async function deliver({ to, subject, text, html }) {
  const from = process.env.MAIL_FROM || "Aegis Security <no-reply@aegis.local>";
  if (mailDevMode()) {
    const line = `\n=== ${new Date().toISOString()} | TO: ${to} | SUBJECT: ${subject} ===\n${text}\n`;
    try {
      fs.appendFileSync(OUTBOX, line);
    } catch (err) {
      console.error("[mailer] outbox write failed:", err.message);
    }
    console.log(`[mailer:dev] ${subject} -> ${to}\n${text}`);
    return { dev: true };
  }
  if (!smtpConfigured()) {
    throw new Error("SMTP is not configured.");
  }
  const transport = buildTransport();
  return transport.sendMail({ from, to, subject, text, html });
}

const appBase = () => (process.env.APP_BASE_URL || "").replace(/\/+$/, "");

const page = (title, inner) => `
  <div style="font-family:Arial,sans-serif;background:#152a4e;padding:32px">
    <div style="max-width:480px;margin:0 auto;background:#111;border:1px solid #39414d;border-radius:14px;padding:28px;color:#e6ecf5">
      <h2 style="margin:0 0 12px;color:#fff">${title}</h2>
      ${inner}
      <p style="margin:24px 0 0;font-size:12px;color:#7c8aa5">Aegis Security Platform</p>
    </div>
  </div>`;

async function sendVerificationEmail(user, token) {
  const url = `${appBase()}/api/auth/verify-email?token=${encodeURIComponent(token)}`;
  const name = escapeHtml(user.name);
  return deliver({
    to: user.email,
    subject: "Verify your Aegis account",
    text: `Hi ${user.name},\n\nVerify your Aegis account within 30 minutes:\n${url}\n\nIf you did not create this account you can ignore this email.`,
    html: page("Verify your Aegis account", `
      <p>Hi ${name},</p>
      <p>Confirm your email within <b>30 minutes</b> to activate your account:</p>
      <p><a href="${url}" style="display:inline-block;background:#2e75b6;color:#fff;padding:10px 18px;border-radius:8px;text-decoration:none;font-weight:bold">Verify email</a></p>
      <p style="font-size:12px;color:#b7c4d8;word-break:break-all">${url}</p>`),
  });
}

async function sendOtpEmail(user, code, purpose) {
  const name = escapeHtml(user.name);
  const subject =
    purpose === "password_reset" ? "Your Aegis password reset code" : "Your Aegis login code";
  const action =
    purpose === "password_reset" ? "reset your password" : "finish signing in";
  return deliver({
    to: user.email,
    subject,
    text: `Hi ${user.name},\n\nYour code to ${action} is: ${code}\n\nIt expires in ${purpose === "password_reset" ? 10 : 5} minutes. If you did not request it, ignore this email.`,
    html: page(subject, `
      <p>Hi ${name},</p>
      <p>Your code to ${action}:</p>
      <p style="font-size:32px;font-weight:bold;letter-spacing:6px;color:#fff">${escapeHtml(code)}</p>
      <p style="font-size:12px;color:#b7c4d8">Expires in ${purpose === "password_reset" ? 10 : 5} minutes.</p>`),
  });
}

async function sendSecurityAlertEmail(user, detail) {
  const name = escapeHtml(user.name);
  const safeDetail = escapeHtml(detail);
  return deliver({
    to: user.email,
    subject: "Aegis security alert",
    text: `Hi ${user.name},\n\nSecurity event on your account: ${detail}\n\nIf this was not you, reset your password immediately.`,
    html: page("Aegis security alert", `
      <p>Hi ${name},</p>
      <p>Security event on your account:</p>
      <p style="background:#20242c;border:1px solid #39414d;border-radius:8px;padding:12px">${safeDetail}</p>
      <p style="font-size:12px;color:#b7c4d8">If this was not you, reset your password immediately.</p>`),
  });
}

module.exports = { sendVerificationEmail, sendOtpEmail, sendSecurityAlertEmail, mailDevMode };

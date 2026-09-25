"use strict";

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");

const db = require("./db");
const mailer = require("./mailer");
const { requireAuth } = require("./middleware/auth");
const { asyncHandler } = require("./middleware/asyncHandler");
const {
  loginLimiter,
  otpLimiter,
  forgotLimiter,
  registerLimiter,
} = require("./middleware/rateLimiter");
const { randomToken, randomOtp, sha256 } = require("./utils/tokens");
const { generateSecret, verifyTotp, keyUri } = require("./utils/totp");

const router = express.Router();

const ACCESS_TTL = process.env.ACCESS_TOKEN_TTL || "15m";
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const PENDING_2FA_TTL = "10m";
const VERIFY_TOKEN_TTL_MS = 30 * 60 * 1000;
const OTP_LOGIN_TTL_MS = 5 * 60 * 1000;
const OTP_RESET_TTL_MS = 10 * 60 * 1000;
const RESET_TOKEN_TTL_MS = 10 * 60 * 1000;
const MAX_LOGIN_FAILS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;
const MAX_OTP_ATTEMPTS = 5;
const BCRYPT_ROUNDS = 12;

// ---------- helpers ----------

const publicUser = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  role: u.role,
  twoFaMethod: u.two_fa_method,
  emailVerified: Boolean(u.email_verified),
});

const { audit } = require("./utils/audit");

const findUserByEmail = (email) =>
  db.prepare("SELECT * FROM users WHERE email = ?").get(String(email || "").toLowerCase());

const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
const PASSWORD_MSG =
  "Password must be at least 8 characters and include upper, lower, digit and special characters.";

const signAccessToken = (user) =>
  jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_ACCESS_SECRET, {
    expiresIn: ACCESS_TTL,
  });

const signPendingToken = (user) =>
  jwt.sign({ sub: user.id, purpose: "2fa" }, process.env.PENDING_2FA_SECRET, {
    expiresIn: PENDING_2FA_TTL,
  });

const verifyPendingToken = (token) => {
  const payload = jwt.verify(token, process.env.PENDING_2FA_SECRET);
  if (payload.purpose !== "2fa") throw new Error("bad purpose");
  return payload;
};

const setRefreshCookie = (res, token) => {
  res.cookie("refreshToken", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/api/auth",
    maxAge: REFRESH_TTL_MS,
  });
};

const issueRefreshToken = (user, res) => {
  const token = randomToken(48);
  db.prepare(
    "INSERT INTO refresh_tokens (id, user_id, token_hash, expires_at, revoked, created_at) VALUES (?,?,?,?,0,?)"
  ).run(uuidv4(), user.id, sha256(token), Date.now() + REFRESH_TTL_MS, Date.now());
  setRefreshCookie(res, token);
};

const revokeAllSessions = (userId) => {
  db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?").run(userId);
};

const insertOtp = (userId, purpose, ttlMs) => {
  const code = randomOtp();
  db.prepare(
    "INSERT INTO otp_codes (id, user_id, code_hash, purpose, expires_at, attempts, consumed, created_at) VALUES (?,?,?,?,?,0,0,?)"
  ).run(uuidv4(), userId, sha256(code), purpose, Date.now() + ttlMs, Date.now());
  return code;
};

// Returns { ok } or { error } — consumes the OTP on success or after MAX_OTP_ATTEMPTS.
const checkOtp = (userId, purpose, code) => {
  const row = db
    .prepare(
      `SELECT * FROM otp_codes
       WHERE user_id = ? AND purpose = ? AND consumed = 0
       ORDER BY created_at DESC LIMIT 1`
    )
    .get(userId, purpose);
  if (!row) return { error: "No active code. Request a new one." };
  if (row.expires_at < Date.now()) {
    db.prepare("UPDATE otp_codes SET consumed = 1 WHERE id = ?").run(row.id);
    return { error: "Code expired. Request a new one." };
  }
  if (sha256(String(code)) === row.code_hash) {
    db.prepare("UPDATE otp_codes SET consumed = 1 WHERE id = ?").run(row.id);
    return { ok: true };
  }
  const attempts = row.attempts + 1;
  db.prepare("UPDATE otp_codes SET attempts = ?, consumed = ? WHERE id = ?").run(
    attempts,
    attempts >= MAX_OTP_ATTEMPTS ? 1 : 0,
    row.id
  );
  if (attempts >= MAX_OTP_ATTEMPTS) {
    return { error: "Too many wrong codes. Request a new one." };
  }
  return { error: "Invalid code." };
};

const escapeHtml = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

const htmlPage = (title, body, ok) => `<!doctype html><html><head><meta charset="utf-8">
<title>${title}</title></head>
<body style="font-family:Arial,sans-serif;background:#152a4e;min-height:100vh;display:flex;align-items:center;justify-content:center;margin:0">
<div style="max-width:440px;background:#111;border:1px solid #39414d;border-radius:14px;padding:32px;color:#e6ecf5;text-align:center">
<h2 style="color:${ok ? "#55c878" : "#f2994a"};margin-top:0">${title}</h2>
<p style="color:#b7c4d8">${body}</p>
<p><a style="color:#7da6e8" href="${escapeHtml(process.env.FRONTEND_URL)}">Return to sign in</a></p>
</div></body></html>`;

// ---------- registration ----------

router.post(
  "/register",
  registerLimiter,
  asyncHandler(async (req, res) => {
    const { name, email, password } = req.body || {};
    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();

    if (!cleanName || cleanName.length > 120) {
      return res.status(400).json({ error: "A valid name is required." });
    }
    if (!/^[^\s@]+@gmail\.com$/.test(cleanEmail)) {
      return res.status(400).json({ error: "Registration requires a @gmail.com address." });
    }
    if (!PASSWORD_RE.test(String(password || ""))) {
      return res.status(400).json({ error: PASSWORD_MSG });
    }
    if (findUserByEmail(cleanEmail)) {
      return res.status(409).json({ error: "An account with this email already exists." });
    }

    const id = uuidv4();
    const verifyToken = randomToken(32);
    const now = Date.now();
    const hash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
    db.prepare(
      `INSERT INTO users (id, name, email, password_hash, role, email_verified,
        email_verify_token, email_verify_expires, two_fa_enabled, two_fa_method,
        created_at, updated_at)
       VALUES (?,?,?,?,'user',0,?,?,1,'email',?,?)`
    ).run(id, cleanName, cleanEmail, hash, sha256(verifyToken), now + VERIFY_TOKEN_TTL_MS, now, now);

    try {
      await mailer.sendVerificationEmail({ name: cleanName, email: cleanEmail }, verifyToken);
    } catch (err) {
      // Roll the user back so a retry is possible; never leak internals.
      db.prepare("DELETE FROM users WHERE id = ?").run(id);
      console.error("[auth] verification email failed:", err.message);
      return res.status(503).json({ error: "Could not send the verification email. Try again later." });
    }

    audit(req, { userId: id, email: cleanEmail, event: "register" });
    return res.status(201).json({ message: "Account created. Check your email to verify it." });
  })
);

router.get("/verify-email", (req, res) => {
  const token = String(req.query.token || "");
  const user = token
    ? db.prepare("SELECT * FROM users WHERE email_verify_token = ?").get(sha256(token))
    : null;
  if (!user || !user.email_verify_expires || user.email_verify_expires < Date.now()) {
    audit(req, { event: "verify_email", detail: "failed" });
    return res
      .status(400)
      .send(htmlPage("Verification failed", "This verification link is invalid or has expired.", false));
  }
  db.prepare(
    "UPDATE users SET email_verified = 1, email_verify_token = NULL, email_verify_expires = NULL, updated_at = ? WHERE id = ?"
  ).run(Date.now(), user.id);
  audit(req, { userId: user.id, email: user.email, event: "verify_email" });
  return res.send(htmlPage("Email verified", "Your Aegis account is now verified. You can sign in.", true));
});

router.post(
  "/resend-verification",
  registerLimiter,
  asyncHandler(async (req, res) => {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const user = email ? findUserByEmail(email) : null;
    if (user && !user.email_verified) {
      const token = randomToken(32);
      db.prepare(
        "UPDATE users SET email_verify_token = ?, email_verify_expires = ?, updated_at = ? WHERE id = ?"
      ).run(sha256(token), Date.now() + VERIFY_TOKEN_TTL_MS, Date.now(), user.id);
      try {
        await mailer.sendVerificationEmail(user, token);
      } catch (err) {
        console.error("[auth] resend verification failed:", err.message);
        return res.status(503).json({ error: "Could not send the email. Try again later." });
      }
      audit(req, { userId: user.id, email, event: "resend_verification" });
    }
    return res.json({ message: "If that account exists and is unverified, a new email is on its way." });
  })
);

// ---------- login + 2FA ----------

router.post(
  "/login",
  loginLimiter,
  asyncHandler(async (req, res) => {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");
    const user = email ? findUserByEmail(email) : null;

    const fail = (event, status, error) => {
      audit(req, { userId: user?.id, email, event });
      return res.status(status).json({ error });
    };

    if (!user) return fail("login_failed", 401, "Invalid email or password.");
    if (user.account_disabled) {
      return fail("login_blocked_disabled", 403, "This account is disabled. Contact an administrator.");
    }
    if (user.lockout_until && user.lockout_until > Date.now()) {
      const mins = Math.ceil((user.lockout_until - Date.now()) / 60000);
      return fail("login_blocked_lockout", 423, `Account locked. Try again in ${mins} minute(s).`);
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      const attempts = user.failed_login_attempts + 1;
      const lock = attempts >= MAX_LOGIN_FAILS ? Date.now() + LOCKOUT_MS : null;
      db.prepare(
        "UPDATE users SET failed_login_attempts = ?, lockout_until = ?, updated_at = ? WHERE id = ?"
      ).run(lock ? 0 : attempts, lock, Date.now(), user.id);
      if (lock) {
        try {
          await mailer.sendSecurityAlertEmail(
            user,
            "Your account was locked for 15 minutes after repeated failed sign-in attempts."
          );
        } catch (err) {
          console.error("[auth] lockout alert email failed:", err.message);
        }
        return fail("login_failed", 423, "Too many failed attempts. Account locked for 15 minutes.");
      }
      return fail("login_failed", 401, "Invalid email or password.");
    }

    if (!user.email_verified) {
      return fail("login_blocked_unverified", 403, "Verify your email before signing in.");
    }

    db.prepare(
      "UPDATE users SET failed_login_attempts = 0, lockout_until = NULL, updated_at = ? WHERE id = ?"
    ).run(Date.now(), user.id);

    const pendingToken = signPendingToken(user);
    if (user.two_fa_method === "totp") {
      audit(req, { userId: user.id, email, event: "2fa_challenge_totp" });
      return res.json({ requires2FA: true, method: "totp", pendingToken });
    }

    const code = insertOtp(user.id, "login_2fa", OTP_LOGIN_TTL_MS);
    try {
      await mailer.sendOtpEmail(user, code, "login_2fa");
    } catch (err) {
      console.error("[auth] login OTP email failed:", err.message);
      return res.status(503).json({ error: "Could not send the login code. Try again later." });
    }
    audit(req, { userId: user.id, email, event: "2fa_sent_email" });
    return res.json({ requires2FA: true, method: "email", pendingToken });
  })
);

router.post(
  "/2fa/verify",
  otpLimiter,
  asyncHandler(async (req, res) => {
    const { pendingToken, code } = req.body || {};
    let payload;
    try {
      payload = verifyPendingToken(String(pendingToken || ""));
    } catch {
      return res.status(401).json({ error: "Sign-in session expired. Start again.", code: "session_expired" });
    }
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(payload.sub);
    if (!user || user.account_disabled) {
      return res.status(401).json({ error: "Sign-in session expired. Start again.", code: "session_expired" });
    }

    let ok = false;
    if (user.two_fa_method === "totp") {
      ok = user.totp_secret ? verifyTotp(String(code || ""), user.totp_secret) : false;
    } else {
      const result = checkOtp(user.id, "login_2fa", code);
      if (!result.ok) {
        audit(req, { userId: user.id, email: user.email, event: "2fa_failed" });
        return res.status(401).json({ error: result.error });
      }
      ok = true;
    }
    if (!ok) {
      audit(req, { userId: user.id, email: user.email, event: "2fa_failed" });
      return res.status(401).json({ error: "Invalid code." });
    }

    issueRefreshToken(user, res);
    audit(req, { userId: user.id, email: user.email, event: "2fa_success" });
    audit(req, { userId: user.id, email: user.email, event: "login_success" });
    return res.json({ accessToken: signAccessToken(user), user: publicUser(user) });
  })
);

router.post(
  "/2fa/resend",
  otpLimiter,
  asyncHandler(async (req, res) => {
    let payload;
    try {
      payload = verifyPendingToken(String(req.body?.pendingToken || ""));
    } catch {
      return res.status(401).json({ error: "Sign-in session expired. Start again.", code: "session_expired" });
    }
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(payload.sub);
    if (!user) return res.status(401).json({ error: "Sign-in session expired. Start again.", code: "session_expired" });
    if (user.two_fa_method === "totp") {
      return res.status(400).json({ error: "This account uses an authenticator app." });
    }
    const code = insertOtp(user.id, "login_2fa", OTP_LOGIN_TTL_MS);
    try {
      await mailer.sendOtpEmail(user, code, "login_2fa");
    } catch (err) {
      console.error("[auth] 2fa resend failed:", err.message);
      return res.status(503).json({ error: "Could not send the code. Try again later." });
    }
    audit(req, { userId: user.id, email: user.email, event: "2fa_resend" });
    return res.json({ message: "A new code was sent." });
  })
);

// ---------- session ----------

router.post("/refresh", (req, res) => {
  const token = req.cookies?.refreshToken;
  if (!token) return res.status(401).json({ error: "No session." });
  const row = db
    .prepare("SELECT * FROM refresh_tokens WHERE token_hash = ?")
    .get(sha256(token));
  if (!row || row.revoked || row.expires_at < Date.now()) {
    res.clearCookie("refreshToken", { path: "/api/auth" });
    return res.status(401).json({ error: "No session." });
  }
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(row.user_id);
  if (!user || user.account_disabled) {
    return res.status(401).json({ error: "No session." });
  }
  // Rotate: revoke the presented token, issue a new one.
  db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?").run(row.id);
  issueRefreshToken(user, res);
  return res.json({ accessToken: signAccessToken(user), user: publicUser(user) });
});

router.post("/logout", (req, res) => {
  const token = req.cookies?.refreshToken;
  if (token) {
    db.prepare("UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?").run(sha256(token));
  }
  res.clearCookie("refreshToken", { path: "/api/auth" });
  return res.json({ message: "Signed out." });
});

router.get("/me", requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

// ---------- password reset (OTP-based) ----------

router.post(
  "/forgot-password",
  forgotLimiter,
  asyncHandler(async (req, res) => {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const user = email ? findUserByEmail(email) : null;
    if (user) {
      const code = insertOtp(user.id, "password_reset", OTP_RESET_TTL_MS);
      try {
        await mailer.sendOtpEmail(user, code, "password_reset");
      } catch (err) {
        console.error("[auth] reset OTP email failed:", err.message);
        return res.status(503).json({ error: "Could not send the email. Try again later." });
      }
      audit(req, { userId: user.id, email, event: "forgot_password_requested" });
    }
    return res.json({ message: "If that account exists, a reset code is on its way." });
  })
);

router.post("/reset-password/verify-otp", forgotLimiter, (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();
  const code = String(req.body?.code || "");
  const user = email ? findUserByEmail(email) : null;
  if (!user) return res.status(400).json({ error: "Invalid or expired code." });
  const result = checkOtp(user.id, "password_reset", code);
  if (!result.ok) return res.status(400).json({ error: result.error });

  const resetToken = randomToken(32);
  db.prepare(
    "UPDATE users SET password_reset_token = ?, password_reset_expires = ?, updated_at = ? WHERE id = ?"
  ).run(sha256(resetToken), Date.now() + RESET_TOKEN_TTL_MS, Date.now(), user.id);
  return res.json({ resetToken });
});

router.post(
  "/reset-password",
  forgotLimiter,
  asyncHandler(async (req, res) => {
    const { resetToken, password } = req.body || {};
    const user = resetToken
      ? db.prepare("SELECT * FROM users WHERE password_reset_token = ?").get(sha256(String(resetToken)))
      : null;
    if (!user || !user.password_reset_expires || user.password_reset_expires < Date.now()) {
      return res.status(400).json({ error: "Invalid or expired reset token." });
    }
    if (!PASSWORD_RE.test(String(password || ""))) {
      return res.status(400).json({ error: PASSWORD_MSG });
    }
    const hash = await bcrypt.hash(String(password), BCRYPT_ROUNDS);
    db.prepare(
      `UPDATE users SET password_hash = ?, password_reset_token = NULL, password_reset_expires = NULL,
        failed_login_attempts = 0, lockout_until = NULL, updated_at = ? WHERE id = ?`
    ).run(hash, Date.now(), user.id);
    revokeAllSessions(user.id);
    try {
      await mailer.sendSecurityAlertEmail(user, "Your password was changed. All sessions were signed out.");
    } catch (err) {
      console.error("[auth] reset alert email failed:", err.message);
    }
    audit(req, { userId: user.id, email: user.email, event: "password_reset" });
    return res.json({ message: "Password updated. You can sign in now." });
  })
);

// ---------- TOTP management ----------

router.post("/2fa/totp/setup", requireAuth, (req, res) => {
  const secret = generateSecret();
  db.prepare("UPDATE users SET totp_pending_secret = ?, updated_at = ? WHERE id = ?").run(
    secret,
    Date.now(),
    req.user.id
  );
  return res.json({ secret, otpauthUrl: keyUri(req.user.email, secret) });
});

router.post("/2fa/totp/confirm", requireAuth, (req, res) => {
  const code = String(req.body?.code || "");
  if (!req.user.totp_pending_secret) {
    return res.status(400).json({ error: "Run TOTP setup first." });
  }
  if (!verifyTotp(code, req.user.totp_pending_secret)) {
    return res.status(400).json({ error: "Invalid code." });
  }
  db.prepare(
    `UPDATE users SET totp_secret = ?, totp_pending_secret = NULL,
      two_fa_method = 'totp', updated_at = ? WHERE id = ?`
  ).run(req.user.totp_pending_secret, Date.now(), req.user.id);
  audit(req, { userId: req.user.id, email: req.user.email, event: "2fa_totp_enabled" });
  return res.json({ message: "Authenticator app enabled." });
});

router.post("/2fa/method/email", requireAuth, (req, res) => {
  db.prepare(
    "UPDATE users SET two_fa_method = 'email', totp_secret = NULL, totp_pending_secret = NULL, updated_at = ? WHERE id = ?"
  ).run(Date.now(), req.user.id);
  audit(req, { userId: req.user.id, email: req.user.email, event: "2fa_method_email" });
  return res.json({ message: "Two-factor method switched to email codes." });
});

module.exports = router;

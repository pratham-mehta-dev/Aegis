import React, { useState } from "react";
import QRCode from "qrcode";
import { api } from "../api.js";
import { Badge, Field, Msg, ShieldIcon, Toast } from "../components/ui.jsx";

// Local heuristic used only when the ML service is unreachable (FR-D3).
const LOCAL_SQLI = /(\bunion\b[\s\S]*\bselect\b)|('|")\s*or\s*'?[\w'"]+\s*=\s*'?\w+|--|\bdrop\s+table\b|\bsleep\s*\(|\bor\s+1\s*=\s*1/i;
const LOCAL_XSS = /<\s*(script|img|svg|iframe|body)\b|on\w+\s*=\s*['"]?\w+\(|javascript:/i;

async function inspectPayload(payload) {
  try {
    return await api.predict({ payload, endpoint: "storefront" });
  } catch (err) {
    if (err.status === 503) {
      const type = LOCAL_SQLI.test(payload) ? "SQL Injection" : LOCAL_XSS.test(payload) ? "XSS" : "Benign";
      return {
        malicious: type !== "Benign",
        type,
        confidence: 0.5,
        severity: { "SQL Injection": "Critical", XSS: "Medium", Benign: "Low" }[type],
        model: "local-regex-fallback",
        alertId: null,
      };
    }
    if (err.status === 403 && err.data?.blocked) {
      return { malicious: true, type: "Blocked Source", severity: "High", alertId: null };
    }
    throw err;
  }
}

const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

export default function Storefront({ session, onLogin, onLogout, onBlocked }) {
  const [tab, setTab] = useState("home");
  return (
    <div>
      <div className="topbar" style={{ background: "#fff", color: "var(--navy)", borderBottom: "1px solid var(--border)" }}>
        <div className="brand" style={{ color: "var(--navy)" }}><ShieldIcon /> Aegis</div>
        <button className={`tab ${tab === "home" ? "active" : ""}`} style={{ color: "var(--muted)" }} onClick={() => setTab("home")}>Home</button>
        <button className={`tab ${tab === "products" ? "active" : ""}`} style={{ color: "var(--muted)" }} onClick={() => setTab("products")}>Products &amp; Reviews</button>
        <div className="spacer" />
        {session && <span className="small muted">Hi, <b>{session.name}</b></span>}
        {session && <button className="btn btn-red btn-sm" onClick={onLogout}>Log out</button>}
      </div>
      <div className="notice">
        Deliberately vulnerable demo storefront — non-credential inputs are inspected by the
        Application Layer Engine before being processed. Passwords are never sent to the detector.
      </div>
      {tab === "home" && !session && <AuthCard onLogin={onLogin} onBlocked={onBlocked} />}
      {tab === "home" && session && <WelcomePanel user={session} />}
      {tab === "products" && <Reviews user={session} onBlocked={onBlocked} />}
    </div>
  );
}

function WelcomePanel({ user }) {
  return (
    <div className="auth-card card center">
      <h2>Welcome, {user.name}.</h2>
      <p className="muted small mt8">Signed in as {user.email} &middot; 2FA: {user.twoFaMethod === "totp" ? "authenticator app" : "email"}</p>
      <p className="small mt8">Open <b>Products &amp; Reviews</b> to post a comment or manage security settings.</p>
    </div>
  );
}

function AuthCard({ onLogin, onBlocked }) {
  const [mode, setMode] = useState("login"); // login | register | forgot | twofa
  const [form, setForm] = useState({ name: "", email: "", password: "", confirm: "", code: "", otp: "", newPass: "", newConfirm: "" });
  const [pending, setPending] = useState(null); // { pendingToken, method }
  const [resetToken, setResetToken] = useState(null);
  const [forgotStep, setForgotStep] = useState(1);
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const run = async (fn) => {
    setBusy(true); setMsg(null);
    try {
      await fn();
    } catch (err) {
      setMsg({ kind: "error", text: err.message });
      if (err?.data?.code === "session_expired") {
        setPending(null);
        setMode("login");
      }
    }
    setBusy(false);
  };

  const submitLogin = () => run(async () => {
    if (!form.email.trim() || !form.password) {
      return setMsg({ kind: "error", text: "Enter your email and password." });
    }
    // IDS inspects the email field only — never the password.
    const verdict = await inspectPayload(form.email);
    if (verdict.malicious) return onBlocked(verdict);
    const res = await api.login({ email: form.email, password: form.password });
    setPending(res);
    setMode("twofa");
  });

  const submit2fa = () => run(async () => {
    const code = form.code.trim();
    if (code.length !== 6) {
      return setMsg({ kind: "error", text: "Enter the 6-digit code." });
    }
    const res = await api.verify2fa({ pendingToken: pending.pendingToken, code });
    onLogin(res);
  });

  const submitRegister = () => run(async () => {
    if (!PASSWORD_RE.test(form.password)) {
      return setMsg({ kind: "error", text: "Password must be 8+ chars with upper, lower, digit and special." });
    }
    if (form.password !== form.confirm) return setMsg({ kind: "error", text: "Passwords do not match." });
    const res = await api.register({ name: form.name, email: form.email, password: form.password });
    setMsg({ kind: "ok", text: res.message + " Then sign in." });
    setMode("login");
  });

  const submitForgot = () => run(async () => {
    if (forgotStep === 1) {
      const res = await api.forgotPassword({ email: form.email });
      setMsg({ kind: "ok", text: res.message });
      setForgotStep(2);
    } else if (forgotStep === 2) {
      const res = await api.resetVerifyOtp({ email: form.email, code: form.otp });
      setResetToken(res.resetToken);
      setForgotStep(3);
      setMsg(null);
    } else {
      if (form.newPass !== form.newConfirm) return setMsg({ kind: "error", text: "Passwords do not match." });
      const res = await api.resetPassword({ resetToken, password: form.newPass });
      setMsg({ kind: "ok", text: res.message });
      setForgotStep(1);
      setMode("login");
    }
  });

  return (
    <div className="auth-card card">
      {mode === "login" && (
        <>
          <h2>Customer Login</h2>
          <p className="muted small">Protected with email verification and mandatory two-factor authentication.</p>
          <Field label="Gmail address"><input className="input" type="email" value={form.email} onChange={set("email")} autoComplete="email" /></Field>
          <Field label="Password">
            <div className="row">
              <input className="input grow" type={showPass ? "text" : "password"} value={form.password} onChange={set("password")} autoComplete="current-password" />
              <button className="btn btn-ghost btn-sm" onClick={() => setShowPass(!showPass)} type="button" aria-label="toggle password visibility">{showPass ? "Hide" : "Show"}</button>
            </div>
          </Field>
          <button className="btn" style={{ width: "100%" }} disabled={busy} onClick={submitLogin}>{busy ? "Signing in..." : "LOG IN"}</button>
          <div className="row mt8" style={{ justifyContent: "space-between" }}>
            <button className="btn btn-ghost btn-sm" onClick={() => { setMode("register"); setMsg(null); }}>Create a new account</button>
            <button className="btn btn-ghost btn-sm" onClick={() => { setMode("forgot"); setForgotStep(1); setMsg(null); }}>Forgot password?</button>
          </div>
          <div className="row mt8">
            <button className="btn btn-ghost btn-sm" onClick={() => run(async () => setMsg({ kind: "ok", text: (await api.resendVerification({ email: form.email })).message }))}>Resend verification email</button>
          </div>
          <p className="muted small mt8">Tip: type <code>' OR '1'='1' --</code> into the email field to trigger detection.</p>
        </>
      )}

      {mode === "register" && (
        <>
          <h2>Create your account</h2>
          <p className="muted small">Use your Gmail address and a strong password.</p>
          <Field label="Full name"><input className="input" value={form.name} onChange={set("name")} autoComplete="name" /></Field>
          <Field label="Gmail address"><input className="input" type="email" value={form.email} onChange={set("email")} autoComplete="email" /></Field>
          <Field label="Password (8+ chars, upper, lower, digit, special)"><input className="input" type="password" value={form.password} onChange={set("password")} autoComplete="new-password" /></Field>
          <Field label="Confirm password"><input className="input" type="password" value={form.confirm} onChange={set("confirm")} autoComplete="new-password" /></Field>
          <button className="btn btn-navy" style={{ width: "100%" }} disabled={busy} onClick={submitRegister}>{busy ? "Creating..." : "CREATE ACCOUNT"}</button>
          <div className="center mt8"><button className="btn btn-ghost btn-sm" onClick={() => setMode("login")}>Back to sign in</button></div>
        </>
      )}

      {mode === "twofa" && (
        <>
          <h2>Verify your sign in</h2>
          <p className="muted small">
            {pending?.method === "totp"
              ? "Enter the 6-digit code from your authenticator app."
              : "Enter the 6-digit code sent to your email."}
          </p>
          <Field label="Code">
            <input className="input center mono" style={{ fontSize: 18, letterSpacing: 4 }} inputMode="numeric" maxLength={6} value={form.code} onChange={set("code")} />
          </Field>
          <button className="btn" style={{ width: "100%" }} disabled={busy} onClick={submit2fa}>{busy ? "Verifying..." : "VERIFY CODE"}</button>
          <div className="row mt8" style={{ justifyContent: "space-between" }}>
            {pending?.method === "email" && (
              <button className="btn btn-ghost btn-sm" onClick={() => run(async () => setMsg({ kind: "ok", text: (await api.resend2fa({ pendingToken: pending.pendingToken })).message }))}>Resend code</button>
            )}
            <button className="btn btn-ghost btn-sm" onClick={() => { setMode("login"); setPending(null); }}>Cancel</button>
          </div>
        </>
      )}

      {mode === "forgot" && (
        <>
          <h2>{forgotStep === 1 ? "Forgot your password?" : forgotStep === 2 ? "Verify reset OTP" : "Choose a new password"}</h2>
          {forgotStep === 1 && (
            <>
              <p className="muted small">Enter your account email and we will send a secure OTP.</p>
              <Field label="Gmail address"><input className="input" type="email" value={form.email} onChange={set("email")} /></Field>
              <button className="btn" style={{ width: "100%" }} disabled={busy} onClick={submitForgot}>{busy ? "Sending..." : "SEND RESET OTP"}</button>
            </>
          )}
          {forgotStep === 2 && (
            <>
              <Field label="6-digit code"><input className="input center mono" style={{ fontSize: 18, letterSpacing: 4 }} inputMode="numeric" maxLength={6} value={form.otp} onChange={set("otp")} /></Field>
              <button className="btn" style={{ width: "100%" }} disabled={busy} onClick={submitForgot}>{busy ? "Verifying..." : "VERIFY OTP"}</button>
            </>
          )}
          {forgotStep === 3 && (
            <>
              <Field label="New password"><input className="input" type="password" value={form.newPass} onChange={set("newPass")} /></Field>
              <Field label="Confirm new password"><input className="input" type="password" value={form.newConfirm} onChange={set("newConfirm")} /></Field>
              <button className="btn" style={{ width: "100%" }} disabled={busy} onClick={submitForgot}>{busy ? "Updating..." : "UPDATE PASSWORD"}</button>
            </>
          )}
          <div className="center mt8"><button className="btn btn-ghost btn-sm" onClick={() => setMode("login")}>Back to sign in</button></div>
        </>
      )}
      <Msg kind={msg?.kind}>{msg?.text}</Msg>
    </div>
  );
}

function Reviews({ user, onBlocked }) {
  const [comment, setComment] = useState("");
  const [comments, setComments] = useState([
    { id: 1, name: "alice92", text: "Love the quick delivery!", flagged: false },
    { id: 2, name: "carol.k", text: "Decent quality for the price.", flagged: false },
  ]);
  const [toast, setToast] = useState("");
  const [busy, setBusy] = useState(false);

  const post = async () => {
    setBusy(true);
    try {
      const verdict = await inspectPayload(comment);
      if (verdict.malicious) {
        if (verdict.type === "XSS") {
          setComments([{ id: Date.now(), name: user?.name || "guest", text: comment, flagged: true }, ...comments]);
          setComment("");
          setBusy(false);
          return setToast("Comment blocked - script tag stripped before render.");
        }
        setBusy(false);
        return onBlocked(verdict);
      }
      setComments([{ id: Date.now(), name: user?.name || "guest", text: comment, flagged: false }, ...comments]);
      setComment("");
      setToast("Review posted.");
    } finally {
      setBusy(false);
    }
    setTimeout(() => setToast(""), 2200);
  };

  return (
    <div className="page" style={{ maxWidth: 720, margin: "0 auto" }}>
      <div className="row">
        <input className="input grow" placeholder="Search products..." />
        <button className="btn btn-navy btn-sm">Search</button>
      </div>
      <h3 className="mt24">Product Reviews</h3>
      <div className="card mt8">
        <Field label="Leave a comment">
          <input className="input" placeholder="Share your thoughts... (try <script>alert(1)</script> to trigger detection)" value={comment} onChange={(e) => setComment(e.target.value)} />
        </Field>
        <button className="btn btn-sm" disabled={busy || !comment.trim()} onClick={post}>Post Review</button>
      </div>
      <div className="card mt16">
        <b className="small">Recent Comments</b>
        {comments.map((c) =>
          c.flagged ? (
            <div key={c.id} className="mt8" style={{ background: "#fdf2f2", border: "1px solid var(--red)", borderRadius: 8, padding: 10 }}>
              <div className="row" style={{ justifyContent: "space-between" }}>
                <b className="small">{c.name}</b>
                <Badge text="XSS" kind="blocked" />
              </div>
              <div className="small muted mono mt8" style={{ textDecoration: "line-through" }}>{c.text}</div>
              <div className="small" style={{ color: "var(--red)" }}>[blocked - script tag stripped before render]</div>
            </div>
          ) : (
            <div key={c.id} className="mt8" style={{ borderBottom: "1px solid var(--border)", paddingBottom: 8 }}>
              <b className="small">{c.name}</b>
              <div className="small mt8">{c.text}</div>
            </div>
          )
        )}
      </div>
      {user && <SecuritySettings user={user} />}
      <Toast text={toast} />
    </div>
  );
}

function SecuritySettings({ user }) {
  const [totp, setTotp] = useState(null); // { secret, otpauthUrl, qr }
  const [code, setCode] = useState("");
  const [toast, setToast] = useState("");
  const say = (t) => { setToast(t); setTimeout(() => setToast(""), 2500); };

  const startSetup = async () => {
    const res = await api.totpSetup();
    const qr = await QRCode.toDataURL(res.otpauthUrl, { width: 180 });
    setTotp({ ...res, qr });
  };
  const confirm = async () => {
    const res = await api.totpConfirm({ code });
    setTotp(null); setCode("");
    say(res.message);
  };
  const backToEmail = async () => {
    const res = await api.useEmail2fa();
    say(res.message);
  };

  return (
    <div className="card mt16">
      <b className="small">Security settings</b>
      <p className="small muted">Current 2FA method: <b>{user.twoFaMethod === "totp" ? "Authenticator app" : "Email codes"}</b></p>
      {user.twoFaMethod === "totp" ? (
        <button className="btn btn-navy btn-sm" onClick={backToEmail}>Switch back to email codes</button>
      ) : !totp ? (
        <button className="btn btn-navy btn-sm" onClick={startSetup}>Enable authenticator app</button>
      ) : (
        <div>
          <p className="small">Scan with your authenticator app, then enter the 6-digit code.</p>
          <img className="qr" src={totp.qr} alt="TOTP QR code" />
          <p className="small mono center">{totp.secret}</p>
          <div className="row">
            <input className="input grow" inputMode="numeric" maxLength={6} placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value)} />
            <button className="btn btn-sm" onClick={confirm}>Confirm</button>
            <button className="btn btn-ghost btn-sm" onClick={() => setTotp(null)}>Cancel</button>
          </div>
        </div>
      )}
      <Toast text={toast} />
    </div>
  );
}

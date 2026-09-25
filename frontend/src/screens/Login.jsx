import React, { useState } from "react";
import { api } from "../api.js";
import { Field, Msg, ShieldIcon } from "../components/ui.jsx";
import { inspectPayload } from "../inspect.js";

const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;

export default function Login({ onLogin, onBlocked }) {
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
    <div className="login-page">
      <div className="login-hero">
        <div className="brand"><ShieldIcon size={30} /> Aegis</div>
        <h1>AI-driven intrusion detection &amp; prevention</h1>
        <p>Real-time payload inspection, mandatory two-factor authentication and a live Security Operations Center.</p>
        <div className="terminal">
          <div><span className="acc">aegis@soc</span>:~$ status --all</div>
          <div><span className="ok">[ OK ]</span> Application layer engine · ML classifier online</div>
          <div><span className="ok">[ OK ]</span> 2FA enforcement · email OTP / TOTP</div>
          <div><span className="ok">[ OK ]</span> Brute-force lockout · rate limiting · IP blocklist</div>
          <div><span className="warn">[WATCH]</span> Monitoring SQLi / XSS signatures <span className="cursor" /></div>
        </div>
        <div className="feature-grid">
          <div className="feature"><b>Customers</b>Storefront, reviews &amp; security settings</div>
          <div className="feature"><b>Analysts</b>SOC Console, alerts, blocklist &amp; simulator</div>
        </div>
      </div>
    <div className="auth-card card">
      {mode === "login" && (
        <>
          <div className="auth-title"><div className="lock"><ShieldIcon size={18} /></div><h2>Secure sign in</h2></div>
          <p className="muted small">One login for customers and SOC analysts. You'll be taken to the right area after two-factor verification.</p>
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
          <div className="auth-title"><div className="lock"><ShieldIcon size={18} /></div><h2>Create your account</h2></div>
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
          <div className="auth-title"><div className="lock"><ShieldIcon size={18} /></div><h2>Two-factor verification</h2></div>
          <p className="muted small">
            {pending?.method === "totp"
              ? "Enter the 6-digit code from your authenticator app."
              : "Enter the 6-digit code sent to your email."}
          </p>
          <Field label="Code">
            <input className="input code-input" inputMode="numeric" maxLength={6} value={form.code} onChange={set("code")} />
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
              <Field label="6-digit code"><input className="input code-input" inputMode="numeric" maxLength={6} value={form.otp} onChange={set("otp")} /></Field>
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
      <div className="secure-foot"><span>TLS</span><span>bcrypt</span><span>JWT</span><span>2FA</span></div>
    </div>
    </div>
  );
}

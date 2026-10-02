import React, { useEffect, useState } from "react";
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
  const [shaking, setShaking] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const [googleEnabled, setGoogleEnabled] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const triggerShake = () => {
    setShaking(false);
    setTimeout(() => setShaking(true), 15);
    setTimeout(() => setShaking(false), 550);
  };

  const run = async (fn) => {
    setBusy(true); setMsg(null);
    try {
      await fn();
    } catch (err) {
      setMsg({ kind: "error", text: err.message });
      triggerShake();
      if (err?.data?.code === "session_expired") {
        setPending(null);
        setMode("login");
      }
    }
    setBusy(false);
  };

  useEffect(() => {
    let active = true;
    api.googleStatus().then(({ enabled }) => {
      if (active) setGoogleEnabled(enabled);
    }).catch(() => {});

    const callbackUrl = new URL(window.location.href);
    const googleResult = callbackUrl.searchParams.get("google");
    if (!googleResult) return () => { active = false; };

    callbackUrl.searchParams.delete("google");
    window.history.replaceState(null, "", `${callbackUrl.pathname}${callbackUrl.search}${callbackUrl.hash}`);
    if (googleResult === "success") {
      api.googlePending().then((res) => {
        if (!active) return;
        setPending(res);
        setMode("twofa");
      }).catch((err) => {
        if (active) setMsg({ kind: "error", text: err.message });
      });
    } else if (active) {
      const messages = {
        cancelled: "Google sign-in was cancelled.",
        state: "Google sign-in expired or could not be verified. Please try again.",
        email: "Continue with a verified Gmail account.",
        disabled: "This account is disabled. Contact an administrator.",
        locked: "This account is temporarily locked. Try again later.",
        challenge: "Could not send your verification code. Try again later.",
        failed: "Google sign-in failed. Please try again.",
      };
      setMsg({ kind: "error", text: messages[googleResult] || messages.failed });
    }
    return () => { active = false; };
  }, []);

  const submitLogin = () => run(async () => {
    if (!form.email.trim() || !form.password) {
      triggerShake();
      return setMsg({ kind: "error", text: "Enter your email and password." });
    }
    // IDS inspects the email field only — never the password.
    const verdict = await inspectPayload(form.email);
    if (verdict.malicious && verdict.type !== "Blocked Source") {
      triggerShake();
      return onBlocked(verdict);
    }
    const res = await api.login({ email: form.email, password: form.password });
    setPending(res);
    setMode("twofa");
  });

  const submit2fa = () => run(async () => {
    const code = form.code.trim();
    if (code.length !== 6) {
      triggerShake();
      return setMsg({ kind: "error", text: "Enter the 6-digit code." });
    }
    const res = await api.verify2fa({ pendingToken: pending.pendingToken, code });
    onLogin(res);
  });

  const submitRegister = () => run(async () => {
    if (!PASSWORD_RE.test(form.password)) {
      triggerShake();
      return setMsg({ kind: "error", text: "Password must be 8+ chars with upper, lower, digit and special." });
    }
    if (form.password !== form.confirm) {
      triggerShake();
      return setMsg({ kind: "error", text: "Passwords do not match." });
    }
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
      if (form.newPass !== form.newConfirm) {
        triggerShake();
        return setMsg({ kind: "error", text: "Passwords do not match." });
      }
      const res = await api.resetPassword({ resetToken, password: form.newPass });
      setMsg({ kind: "ok", text: res.message });
      setForgotStep(1);
      setMode("login");
    }
  });

  const handleFormKeyDown = (event) => {
    if (event.key !== "Enter" || event.repeat || event.isComposing || busy || event.target.tagName !== "INPUT") return;
    event.preventDefault();
    if (mode === "login") submitLogin();
    else if (mode === "register") submitRegister();
    else if (mode === "twofa") submit2fa();
    else if (mode === "forgot") submitForgot();
  };

  return (
    <div className="login-page">
      <div className="login-hero">
        <div className="hero-brand-row">
          <div className="shield-radar-box">
            <div className="radar-ring" />
            <div className="radar-ring" />
            <div className="radar-ring" />
            <ShieldIcon size={32} className="shield-icon-animated" />
          </div>
          <div className="brand">Aegis Security</div>
        </div>
        <h1>AI-driven intrusion detection &amp; prevention</h1>

        <div className="pipeline-wrapper">
          <div className="pipe-step step-cyan">
            <div className="pipe-node-col">
              <div className="pipe-node-dot">
                <div className="node-core" />
                <div className="node-pulse" />
              </div>
              <div className="pipe-line-segment seg-1" />
            </div>
            <div className="pipe-content">
              <span className="pipe-phase-tag tag-cyan">Phase 01</span>
              <span className="pipe-title">Intercept &amp; Payload Inspection</span>
            </div>
          </div>

          <div className="pipe-step step-purple">
            <div className="pipe-node-col">
              <div className="pipe-node-dot">
                <div className="node-core" />
                <div className="node-pulse" />
              </div>
              <div className="pipe-line-segment seg-2" />
            </div>
            <div className="pipe-content">
              <span className="pipe-phase-tag tag-purple">Phase 02</span>
              <span className="pipe-title">AI Confidence &amp; Threat Scoring</span>
            </div>
          </div>

          <div className="pipe-step step-green">
            <div className="pipe-node-col">
              <div className="pipe-node-dot">
                <div className="node-core" />
                <div className="node-pulse" />
              </div>
            </div>
            <div className="pipe-content">
              <span className="pipe-phase-tag tag-green">Phase 03</span>
              <span className="pipe-title">Instant Block &amp; SOC Alerting</span>
            </div>
          </div>
        </div>
      </div>
      <div className={`auth-card card ${shaking ? "shake" : ""}`}>
        <div key={`${mode}-${forgotStep}`} className="form-mode-container" onKeyDown={handleFormKeyDown}>
          {mode === "login" && (
            <>
              <div className="auth-title">
                <div className="lock"><ShieldIcon size={18} /></div>
                <h2>Secure sign in</h2>
              </div>
              <div className="auth-divider" />
              <Field label="Email address">
                <input className="input" type="email" value={form.email} onChange={set("email")} autoComplete="email" placeholder="you@example.com" />
              </Field>
              <div className="password-field-wrapper">
                <Field label="Password">
                  <div className="row">
                    <input className="input grow" type={showPass ? "text" : "password"} value={form.password} onChange={set("password")} autoComplete="current-password" placeholder="••••••••" />
                    <button className="btn btn-ghost btn-sm" onClick={() => setShowPass(!showPass)} type="button" aria-label="toggle password visibility">{showPass ? "Hide" : "Show"}</button>
                  </div>
                </Field>
                <div className="forgot-link-row">
                  <button className="auth-link forgot-link" onClick={() => { setMode("forgot"); setForgotStep(1); setMsg(null); }}>Forgot password?</button>
                </div>
              </div>
              <button className={`btn btn-primary-full ${busy ? "loading" : ""}`} disabled={busy} onClick={submitLogin}>
                {busy ? "Signing in..." : "Sign In"}
              </button>
              {googleEnabled && (
                <button className="google-signin" type="button" disabled={busy} onClick={() => window.location.assign("/api/auth/google")}>
                  <svg className="google-mark" viewBox="0 0 48 48" aria-hidden="true">
                    <path fill="#4285F4" d="M43.6 20.1H42V20H24v8h11.3c-1.6 4.7-6 8-11.3 8-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 8 3.1l5.7-5.7C34 6.1 29.3 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.3-.1-2.6-.4-3.9z" />
                    <path fill="#34A853" d="M6.3 14.7l6.6 4.8C14.7 16 19 12 24 12c3.1 0 5.8 1.2 8 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z" />
                    <path fill="#FBBC05" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.1 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-7.9l-6.5 5C9.5 39.6 16.2 44 24 44z" />
                    <path fill="#EA4335" d="M12.7 28.1 6.2 33.1C4.8 30.4 4 27.3 4 24s.8-6.4 2.2-9.1l6.6 4.8C12.3 21.1 12 22.5 12 24s.3 2.9.7 4.1z" />
                  </svg>
                  <span>Continue with Google</span>
                </button>
              )}
              <div className="auth-links-row">
                <button className="auth-link" onClick={() => { setMode("register"); setMsg(null); }}>Create account</button>
                <span className="auth-link-sep">·</span>
                <button className="auth-link" onClick={() => run(async () => setMsg({ kind: "ok", text: (await api.resendVerification({ email: form.email })).message }))}>Resend verification</button>
              </div>
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
              <button className={`btn btn-navy ${busy ? "loading" : ""}`} style={{ width: "100%" }} disabled={busy} onClick={submitRegister}>{busy ? "Creating..." : "CREATE ACCOUNT"}</button>
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
              <button className={`btn ${busy ? "loading" : ""}`} style={{ width: "100%" }} disabled={busy} onClick={submit2fa}>{busy ? "Verifying..." : "VERIFY CODE"}</button>
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
                  <button className={`btn ${busy ? "loading" : ""}`} style={{ width: "100%" }} disabled={busy} onClick={submitForgot}>{busy ? "Sending..." : "SEND RESET OTP"}</button>
                </>
              )}
              {forgotStep === 2 && (
                <>
                  <Field label="6-digit code"><input className="input code-input" inputMode="numeric" maxLength={6} value={form.otp} onChange={set("otp")} /></Field>
                  <button className={`btn ${busy ? "loading" : ""}`} style={{ width: "100%" }} disabled={busy} onClick={submitForgot}>{busy ? "Verifying..." : "VERIFY OTP"}</button>
                </>
              )}
              {forgotStep === 3 && (
                <>
                  <Field label="New password"><input className="input" type="password" value={form.newPass} onChange={set("newPass")} /></Field>
                  <Field label="Confirm new password"><input className="input" type="password" value={form.newConfirm} onChange={set("newConfirm")} /></Field>
                  <button className={`btn ${busy ? "loading" : ""}`} style={{ width: "100%" }} disabled={busy} onClick={submitForgot}>{busy ? "Updating..." : "UPDATE PASSWORD"}</button>
                </>
              )}
              <div className="center mt8"><button className="btn btn-ghost btn-sm" onClick={() => setMode("login")}>Back to sign in</button></div>
            </>
          )}
        </div>
        <Msg kind={msg?.kind}>{msg?.text}</Msg>
      </div>
    </div>
  );
}

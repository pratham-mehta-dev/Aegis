import React, { useState } from "react";
import { api } from "../api.js";
import { Field, Msg, ShieldIcon } from "../components/ui.jsx";

export default function SocLogin({ onLogin }) {
  const [form, setForm] = useState({ email: "", password: "", code: "" });
  const [pending, setPending] = useState(null);
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const [showPass, setShowPass] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  const submit = async () => {
    setBusy(true); setMsg(null);
    try {
      if (!pending) {
        const res = await api.login({ email: form.email, password: form.password });
        setPending(res);
      } else {
        const res = await api.verify2fa({ pendingToken: pending.pendingToken, code: form.code });
        if (res.user.role !== "admin") {
          return setMsg({ kind: "error", text: "This account is not authorized for the SOC Console." });
        }
        onLogin(res);
      }
    } catch (err) {
      setMsg({ kind: "error", text: err.message });
    }
    setBusy(false);
  };

  return (
    <div style={{ minHeight: "calc(100vh - 56px)", background: "var(--navy-dark)", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div className="card" style={{ maxWidth: 360, width: "100%" }}>
        <div className="center">
          <div style={{ display: "inline-flex", background: "var(--navy)", color: "#fff", borderRadius: 10, padding: 10 }}><ShieldIcon size={22} /></div>
          <h2 className="mt8">SOC Console Login</h2>
          <p className="muted small">Restricted access — authorized security personnel only</p>
        </div>
        {!pending ? (
          <>
            <Field label="Email"><input className="input" type="email" value={form.email} onChange={set("email")} /></Field>
            <Field label="Password">
              <div className="row">
                <input className="input grow" type={showPass ? "text" : "password"} value={form.password} onChange={set("password")} />
                <button className="btn btn-ghost btn-sm" type="button" onClick={() => setShowPass(!showPass)}>{showPass ? "Hide" : "Show"}</button>
              </div>
            </Field>
            <button className="btn" style={{ width: "100%" }} disabled={busy} onClick={submit}>{busy ? "Signing in..." : "SIGN IN"}</button>
          </>
        ) : (
          <>
            <p className="small muted">{pending.method === "totp" ? "Enter the code from your authenticator app." : "Enter the 6-digit code sent to your email."}</p>
            <Field label="Code"><input className="input center mono" style={{ fontSize: 18, letterSpacing: 4 }} inputMode="numeric" maxLength={6} value={form.code} onChange={set("code")} /></Field>
            <button className="btn" style={{ width: "100%" }} disabled={busy} onClick={submit}>{busy ? "Verifying..." : "VERIFY"}</button>
            <div className="center mt8"><button className="btn btn-ghost btn-sm" onClick={() => setPending(null)}>Back</button></div>
          </>
        )}
        <Msg kind={msg?.kind}>{msg?.text}</Msg>
      </div>
    </div>
  );
}

import React, { useState } from "react";
import QRCode from "qrcode";
import { api } from "../api.js";
import { Badge, Field, ShieldIcon, Toast } from "../components/ui.jsx";
import { inspectPayload } from "../inspect.js";

export default function Storefront({ session, onBlocked }) {
  const [tab, setTab] = useState("home");
  return (
    <div>
      <div className="topbar subbar">
        <div className="brand"><ShieldIcon /> Storefront</div>
        <button className={`tab ${tab === "home" ? "active" : ""}`} onClick={() => setTab("home")}>Home</button>
        <button className={`tab ${tab === "products" ? "active" : ""}`} onClick={() => setTab("products")}>Products &amp; Reviews</button>
        <div className="spacer" />
        <span className="small muted">Hi, <b>{session.name}</b></span>
      </div>
      <div className="notice">
        Deliberately vulnerable demo storefront — non-credential inputs are inspected by the
        Application Layer Engine before being processed. Passwords are never sent to the detector.
      </div>
      {tab === "home" && <WelcomePanel user={session} />}
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
            <div key={c.id} className="mt8 flagged">
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

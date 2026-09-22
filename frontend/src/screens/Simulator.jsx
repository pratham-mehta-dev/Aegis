import React, { useState } from "react";
import { api } from "../api.js";
import { Badge, Msg } from "../components/ui.jsx";

// Mock presets are clearly identified as demo launchers (rules.md §7).
const NETWORK_PRESETS = [
  { type: "Port Scan", tool: "nmap -sS", color: "var(--orange)", desc: "TCP SYN sweep across ports" },
  { type: "DoS Flood", tool: "hping3 --flood", color: "var(--red)", desc: "SYN flood against target" },
  { type: "Brute Force", tool: "hydra ssh", color: "var(--orange)", desc: "Credential stuffing on SSH" },
];
const APP_PRESETS = [
  { type: "SQL Injection", payload: "' OR '1'='1' --", color: "var(--red)", desc: "Auth bypass attempt" },
  { type: "XSS", payload: "<script>alert(document.cookie)</script>", color: "#c9a227", desc: "Stored XSS in comment" },
  { type: "Benign", payload: "Great product, works as described!", color: "var(--green)", desc: "Control: normal traffic" },
];

export default function Simulator({ onViewAlert }) {
  const [result, setResult] = useState(null);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState("");

  const launch = async (preset) => {
    setBusy(preset.type); setErr(null); setResult(null);
    try {
      const res = preset.payload !== undefined
        ? await api.predict({ payload: preset.payload, endpoint: "attack-simulator" })
        : await api.simulate({ type: preset.type });
      setResult({ ...res, launched: preset.type });
    } catch (e) {
      setErr(e.message);
    }
    setBusy("");
  };

  const PresetRow = ({ p }) => (
    <div className="preset">
      <div className="bar" style={{ background: p.color }} />
      <div className="grow">
        <b className="small">{p.type}</b>
        <div className="small muted">{p.desc}{p.tool ? ` · ${p.tool}` : ""}</div>
      </div>
      <button className="btn btn-sm" style={{ background: p.color }} disabled={!!busy} onClick={() => launch(p)}>
        {busy === p.type ? "Launching…" : "Launch"}
      </button>
    </div>
  );

  return (
    <div className="page" style={{ maxWidth: 900, margin: "0 auto" }}>
      <div className="card" style={{ background: "var(--navy)", color: "#fff", border: "none" }}>
        <b>Attack Simulator — Demo Mode</b>
        <p className="small" style={{ color: "#c7d3e8" }}>
          Preset attacks for demos. Application-layer presets run through the real ML engine;
          network-layer presets create clearly-labelled <i>simulated</i> alerts (no packet capture exists in this prototype).
        </p>
      </div>
      <div className="grid mt16" style={{ gridTemplateColumns: "1fr 1fr" }}>
        <div className="card">
          <b className="small">Network Layer <span className="muted">(simulated)</span></b>
          <div className="mt8">{NETWORK_PRESETS.map((p) => <PresetRow key={p.type} p={p} />)}</div>
        </div>
        <div className="card">
          <b className="small">Application Layer <span className="muted">(real ML)</span></b>
          <div className="mt8">{APP_PRESETS.map((p) => <PresetRow key={p.type} p={p} />)}</div>
        </div>
      </div>
      <div className="card mt16">
        <b className="small">Live Detection Result</b>
        {!result && !err && <p className="muted small mt8">Launch a preset to see the verdict.</p>}
        {err && <Msg kind="error">{err}</Msg>}
        {result && (
          <div className="mt8">
            <div className="row">
              <Badge text={result.type} />
              <Badge text={result.severity} />
              {result.simulated ? <span className="badge status-new">simulated</span> : null}
              <b className="small">{result.launched} — SENT</b>
            </div>
            <p className="small mt8">
              {result.layer || "Application"} Layer Engine classified the request as{" "}
              <b>{result.malicious ? "MALICIOUS" : "BENIGN"}</b> (confidence {Number(result.confidence).toFixed(2)})
              {result.alertId ? <> — alert <code>{result.alertId}</code></> : ""}.
            </p>
            {result.alertId && (
              <button className="btn btn-navy btn-sm" onClick={() => onViewAlert(result.alertId)}>View in SOC Dashboard &rarr;</button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

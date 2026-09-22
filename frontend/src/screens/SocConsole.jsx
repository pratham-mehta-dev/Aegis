import React, { useEffect, useState } from "react";
import { api, getAccessToken } from "../api.js";
import { Badge, Kpi, Modal, Toast, fmtTime } from "../components/ui.jsx";

const SEV_COLOR = { Critical: "var(--red)", High: "var(--orange)", Medium: "var(--yellow)", Low: "var(--green)" };
const TABS = ["Overview", "Alerts", "Blocked & Reports", "Model"];

export default function SocConsole({ user, onLogout, focusAlert }) {
  const [tab, setTab] = useState("Overview");
  const [stats, setStats] = useState(null);
  const [toast, setToast] = useState("");
  const say = (t) => { setToast(t); setTimeout(() => setToast(""), 2400); };

  useEffect(() => {
    let live = true;
    const load = () => api.adminStats().then((s) => live && setStats(s)).catch(() => {});
    load();
    const t = setInterval(load, 5000);
    return () => { live = false; clearInterval(t); };
  }, []);

  useEffect(() => { if (focusAlert) setTab("Alerts"); }, [focusAlert]);

  return (
    <div style={{ display: "flex" }}>
      <div className="sidebar">
        {TABS.map((t) => (
          <button key={t} className={tab === t ? "active" : ""} onClick={() => setTab(t)}>{t}</button>
        ))}
        <div className="who">Signed in as<br />{user.email}</div>
      </div>
      <div className="page grow">
        {tab === "Overview" && <Overview stats={stats} goAlerts={() => setTab("Alerts")} />}
        {tab === "Alerts" && <Alerts say={say} focusAlert={focusAlert} />}
        {tab === "Blocked & Reports" && <Blocked say={say} />}
        {tab === "Model" && <ModelInfo />}
      </div>
      <Toast text={toast} />
    </div>
  );
}

function Overview({ stats, goAlerts }) {
  if (!stats) return <p className="muted">Loading live data…</p>;
  const dist = stats.byType || [];
  const distTotal = dist.reduce((a, b) => a + b.n, 0);
  const feed = stats.feed || [];
  const heat = feed.slice(0, 28);
  return (
    <div>
      <div className="grid grid-4">
        <Kpi label="Total alerts (24h)" value={stats.total24h} color="var(--accent)" />
        <Kpi label="Critical" value={stats.critical24h} color="var(--red)" />
        <Kpi label="Blocked sources" value={stats.blockedSources} color="var(--orange)" />
        <Kpi label="Detection model" value={stats.model || "—"} color="var(--green)" />
      </div>
      <div className="grid grid-2 mt16">
        <div className="card">
          <div className="row" style={{ justifyContent: "space-between" }}>
            <b className="small"><span className="live-dot" />Live Alert Feed</b>
            <button className="btn btn-ghost btn-sm" onClick={goAlerts}>View all &rarr;</button>
          </div>
          <div className="mt8">
            {feed.slice(0, 8).map((a) => (
              <div className="feed-row" key={a.id}>
                <span className="muted mono" style={{ width: 150 }}>{new Date(a.created_at).toLocaleTimeString()}</span>
                <span style={{ width: 80 }}>{a.layer}{a.simulated ? "*" : ""}</span>
                <span className="grow">{a.type}</span>
                <span className="mono muted">{a.source_ip || "—"}</span>
                <Badge text={a.severity} />
              </div>
            ))}
            {!feed.length && <p className="muted small">No alerts yet — launch one from the Attack Simulator.</p>}
          </div>
          <p className="small muted mt8">* simulated network-layer event</p>
        </div>
        <div>
          <div className="card">
            <b className="small">Attack-Type Distribution</b>
            {distTotal ? (
              <>
                <div className="dist-bar mt8">
                  {dist.map((d) => (
                    <div key={d.type} className="dist-seg" title={`${d.type}: ${d.n}`} style={{ width: `${(d.n / distTotal) * 100}%`, background: SEV_COLOR[sevOf(d.type)] || "var(--accent)" }} />
                  ))}
                </div>
                <div className="mt8">
                  {dist.map((d) => (
                    <div className="row small" key={d.type}>
                      <span style={{ width: 10, height: 10, borderRadius: 2, background: SEV_COLOR[sevOf(d.type)] || "var(--accent)", display: "inline-block" }} />
                      <span className="grow">{d.type}</span><b>{d.n}</b>
                    </div>
                  ))}
                </div>
              </>
            ) : <p className="muted small mt8">No malicious detections in the last 24h.</p>}
          </div>
          <div className="card mt16">
            <b className="small">Severity Heatmap (recent)</b>
            <div className="heat mt8">
              {Array.from({ length: 28 }).map((_, i) => (
                <div key={i} className="heat-cell" title={heat[i] ? `${heat[i].type} — ${heat[i].severity}` : "no data"} style={{ background: heat[i] ? SEV_COLOR[heat[i].severity] : "#e3e8ef" }} />
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

const sevOf = (type) =>
  ({ "SQL Injection": "Critical", "DoS Flood": "Critical", "Port Scan": "High", "Brute Force": "High", XSS: "Medium" }[type] || "Low");

function Alerts({ say, focusAlert }) {
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [filters, setFilters] = useState({ layer: "", severity: "", q: "" });
  const [detail, setDetail] = useState(null);
  const [page, setPage] = useState(1);

  const load = async (p = page, f = filters) => {
    const qs = new URLSearchParams({ page: p, limit: 20 });
    if (f.layer) qs.set("layer", f.layer);
    if (f.severity) qs.set("severity", f.severity);
    if (f.q) qs.set("q", f.q);
    const res = await api.adminAlerts(qs.toString());
    setAlerts(res.alerts); setTotal(res.total); setPage(res.page);
  };

  useEffect(() => { load(1, filters); }, [filters]);
  useEffect(() => {
    if (focusAlert) {
      api.adminAlert(focusAlert).then((r) => setDetail(r.alert)).catch(() => {});
    }
  }, [focusAlert]);

  const act = async (id, action) => {
    try {
      if (action === "blocklist") {
        const alert = detail;
        await api.adminBlock({ ip: alert.source_ip, reason: `From alert ${alert.id}: ${alert.type}` });
        say(`${alert.source_ip} added to blocklist.`);
      } else {
        const res = await api.adminPatchAlert(id, action);
        say(`Alert ${res.status}.`);
      }
      setDetail(null); load();
    } catch (err) { say(err.message); }
  };

  return (
    <div className="card">
      <div className="row">
        <b className="grow">Alerts</b>
        {["", "Application", "Network"].map((l) => (
          <button key={l || "all"} className={`pill ${filters.layer === l ? "active" : ""}`} onClick={() => setFilters({ ...filters, layer: l })}>{l || "All"}</button>
        ))}
        <select className="input" value={filters.severity} onChange={(e) => setFilters({ ...filters, severity: e.target.value })}>
          <option value="">All severities</option>
          {["Critical", "High", "Medium", "Low"].map((s) => <option key={s}>{s}</option>)}
        </select>
        <input className="input" style={{ width: 160 }} placeholder="Source IP…" value={filters.q} onChange={(e) => setFilters({ ...filters, q: e.target.value })} />
      </div>
      <div className="table-wrap mt8">
        <table className="table">
          <thead><tr><th>Alert ID</th><th>Layer</th><th>Attack Type</th><th>Source IP</th><th>Conf.</th><th>Severity</th><th>Status</th><th></th></tr></thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.id}>
                <td className="mono">{a.id}{a.simulated ? "*" : ""}</td>
                <td>{a.layer}</td>
                <td>{a.type}</td>
                <td className="mono">{a.source_ip || "—"}</td>
                <td>{Number(a.confidence).toFixed(2)}</td>
                <td><Badge text={a.severity} /></td>
                <td><Badge text={a.status} kind={a.status} /></td>
                <td><button className="btn btn-ghost btn-sm" onClick={() => api.adminAlert(a.id).then((r) => setDetail(r.alert))}>View</button></td>
              </tr>
            ))}
            {!alerts.length && <tr><td colSpan={8} className="muted center">No alerts match these filters.</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="row mt8">
        <span className="small muted grow">{total} alert(s)</span>
        <button className="btn btn-ghost btn-sm" disabled={page <= 1} onClick={() => load(page - 1)}>&larr; Prev</button>
        <button className="btn btn-ghost btn-sm" disabled={page * 20 >= total} onClick={() => load(page + 1)}>Next &rarr;</button>
      </div>

      {detail && (
        <Modal onClose={() => setDetail(null)}>
          <div className="row">
            <h3 className="grow">{detail.id} — {detail.type} Detected</h3>
            <Badge text={detail.severity} />
            <Badge text={detail.status} kind={detail.status} />
            {detail.simulated ? <Badge text="simulated" kind="new" /> : null}
          </div>
          <p className="small muted mt8">{detail.layer} Layer &middot; {detail.model || "unknown model"} &middot; confidence {Number(detail.confidence).toFixed(2)} &middot; {fmtTime(detail.created_at)}</p>
          <div className="detail-grid mt8">
            <div className="detail-item"><div className="k">Source IP</div>{detail.source_ip || "—"}</div>
            <div className="detail-item"><div className="k">Target Endpoint</div>{detail.endpoint || "—"}</div>
            <div className="detail-item"><div className="k">Layer</div>{detail.layer}</div>
            <div className="detail-item"><div className="k">Model Used</div>{detail.model || "—"}</div>
          </div>
          <p className="small mt16"><b>Raw Payload (captured)</b></p>
          <div className="payload-box">{detail.payload || "—"}</div>
          <div className="row mt16">
            <button className="btn btn-red" onClick={() => act(detail.id, "confirm")}>Confirm &amp; Keep Blocked</button>
            <button className="btn" onClick={() => act(detail.id, "false_positive")}>Mark False Positive</button>
            <button className="btn btn-navy" onClick={() => act(detail.id, "blocklist")}>Add to Blocklist</button>
          </div>
        </Modal>
      )}
    </div>
  );
}

function Blocked({ say }) {
  const [rows, setRows] = useState([]);
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  const [showForm, setShowForm] = useState(false);

  const load = () => api.adminBlocklist().then((r) => setRows(r.blocked)).catch(() => {});
  useEffect(load, []);

  const block = async () => {
    try {
      const res = await api.adminBlock({ ip, reason });
      say(res.message); setIp(""); setReason(""); setShowForm(false); load();
    } catch (err) { say(err.message); }
  };
  const unblock = async (target) => {
    try { const res = await api.adminUnblock(target); say(res.message); load(); }
    catch (err) { say(err.message); }
  };

  return (
    <div>
      <div className="card">
        <div className="row">
          <b className="grow">Blocked Sources</b>
          <button className="btn btn-red btn-sm" onClick={() => setShowForm(!showForm)}>Manually Block IP</button>
        </div>
        {showForm && (
          <div className="row mt8">
            <input className="input" style={{ width: 180 }} placeholder="IP address" value={ip} onChange={(e) => setIp(e.target.value)} />
            <input className="input grow" placeholder="Reason" value={reason} onChange={(e) => setReason(e.target.value)} />
            <button className="btn btn-sm" onClick={block}>Block</button>
          </div>
        )}
        <div className="table-wrap mt8">
          <table className="table">
            <thead><tr><th>Source IP</th><th>Reason</th><th>Layer</th><th>Blocked Since</th><th>Alerts</th><th></th></tr></thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td className="mono">{r.ip}</td>
                  <td>{r.reason}</td>
                  <td>{r.layer || "—"}</td>
                  <td>{fmtTime(r.created_at)}</td>
                  <td>{r.alert_count}</td>
                  <td><button className="btn btn-ghost btn-sm" onClick={() => unblock(r.ip)}>Unblock</button></td>
                </tr>
              ))}
              {!rows.length && <tr><td colSpan={6} className="muted center">No sources currently blocked.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
      <div className="card mt16">
        <b className="small">Reports &amp; Export</b>
        <p className="small muted">Exports include alert metadata only (no credential data is stored in alerts).</p>
        <div className="row mt8">
          <button className="btn btn-sm" onClick={() => downloadCsv().then(say).catch((e) => say(e.message))}>Export CSV</button>
        </div>
      </div>
    </div>
  );
}

async function downloadCsv() {
  const res = await fetch("/api/admin/alerts/export.csv", {
    headers: { Authorization: `Bearer ${getAccessToken()}` },
  });
  if (!res.ok) throw new Error("Export failed.");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "aegis-alerts.csv"; a.click();
  URL.revokeObjectURL(url);
  return "CSV downloaded.";
}

function ModelInfo() {
  const [info, setInfo] = useState(null);
  useEffect(() => { api.modelInfo().then(setInfo).catch(() => setInfo({ online: false })); }, []);
  return (
    <div>
      <div className="card">
        <b className="small">Application Layer Model</b>
        {!info ? <p className="muted small">Loading…</p> : !info.online ? (
          <p className="small mt8" style={{ color: "var(--red)" }}>ML service offline — storefront falls back to the local regex heuristic.</p>
        ) : (
          <div className="detail-grid mt8">
            <div className="detail-item"><div className="k">Algorithm</div>{info.model}</div>
            <div className="detail-item"><div className="k">Version</div>{info.version}</div>
            <div className="detail-item"><div className="k">Classes</div>{(info.classes || []).join(", ")}</div>
            <div className="detail-item"><div className="k">Training samples</div>{info.training_samples}</div>
          </div>
        )}
        {info?.note && <p className="small muted mt8">{info.note}</p>}
      </div>
      <div className="card mt16">
        <b className="small">Network Layer Model</b>
        <p className="small muted mt8">Simulated — no packet capture in this prototype. Network-layer alerts are generated by the Attack Simulator and marked <i>simulated</i>.</p>
      </div>
    </div>
  );
}

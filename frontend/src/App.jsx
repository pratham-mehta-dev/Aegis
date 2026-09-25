import React, { useEffect, useState } from "react";
import { api, setAccessToken, setSessionExpiredHandler, tryRefresh } from "./api.js";
import { ShieldIcon } from "./components/ui.jsx";
import AccessDenied from "./screens/AccessDenied.jsx";
import Login from "./screens/Login.jsx";
import Simulator from "./screens/Simulator.jsx";
import SocConsole from "./screens/SocConsole.jsx";
import Storefront from "./screens/Storefront.jsx";

const homeView = (user) => (user?.role === "admin" ? "soc" : "storefront");

export default function App() {
  const [view, setView] = useState("storefront"); // storefront | soc | simulator | denied
  const [session, setSession] = useState(null);
  const [denied, setDenied] = useState(null);
  const [focusAlert, setFocusAlert] = useState(null);
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    setSessionExpiredHandler(() => setSession(null));
    (async () => {
      const user = await tryRefresh();
      if (user && user !== true) {
        setSession(user);
        setView(homeView(user));
      }
      setBooting(false);
    })();
  }, []);

  const onLogin = ({ accessToken, user }) => {
    setAccessToken(accessToken);
    setSession(user);
    setView(homeView(user));
  };

  const onLogout = async () => {
    try { await api.logout(); } catch { /* best effort */ }
    setAccessToken(null);
    setSession(null);
    setView("storefront");
  };

  const onBlocked = (verdict) => {
    setDenied({ type: verdict.type, alertId: verdict.alertId });
    setView("denied");
  };

  if (booting) {
    return <div className="center" style={{ marginTop: 120 }}><ShieldIcon size={32} /><p className="muted">Loading Aegis…</p></div>;
  }
  if (view === "denied") {
    return <AccessDenied type={denied.type} alertId={denied.alertId} onBack={() => setView(homeView(session))} />;
  }
  if (!session) {
    return <Login onLogin={onLogin} onBlocked={onBlocked} />;
  }

  const isAdmin = session.role === "admin";
  const tabs = isAdmin
    ? [["soc", "SOC Console"], ["storefront", "Demo Storefront"], ["simulator", "Attack Simulator"]]
    : [["storefront", "Demo Storefront"]];
  const current = tabs.some(([id]) => id === view) ? view : homeView(session);

  return (
    <div>
      <div className="topbar">
        <div className="brand"><ShieldIcon /> Aegis Security Platform</div>
        <div className="spacer" />
        {tabs.map(([id, label]) => (
          <button key={id} className={`tab ${current === id ? "active" : ""}`} onClick={() => setView(id)}>{label}</button>
        ))}
        <span className="user-chip">{session.name}<span className="role-pill">{session.role}</span></span>
        <button className="btn btn-red btn-sm" onClick={onLogout}>Log Out</button>
      </div>

      {current === "soc" && <SocConsole user={session} onLogout={onLogout} focusAlert={focusAlert} />}
      {current === "storefront" && <Storefront session={session} onBlocked={onBlocked} />}
      {current === "simulator" && (
        <Simulator onViewAlert={(id) => { setFocusAlert(id); setView("soc"); }} />
      )}
    </div>
  );
}

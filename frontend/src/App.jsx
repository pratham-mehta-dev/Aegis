import React, { useEffect, useState } from "react";
import { api, setAccessToken, setSessionExpiredHandler, tryRefresh } from "./api.js";
import { ShieldIcon } from "./components/ui.jsx";
import AccessDenied from "./screens/AccessDenied.jsx";
import Simulator from "./screens/Simulator.jsx";
import SocConsole from "./screens/SocConsole.jsx";
import SocLogin from "./screens/SocLogin.jsx";
import Storefront from "./screens/Storefront.jsx";

export default function App() {
  const [view, setView] = useState("storefront"); // storefront | soc-login | soc | simulator | denied
  const [session, setSession] = useState(null);   // { user, ... }
  const [denied, setDenied] = useState(null);
  const [focusAlert, setFocusAlert] = useState(null);
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    setSessionExpiredHandler(() => setSession(null));
    (async () => {
      const user = await tryRefresh();
      if (user && user !== true) setSession(user);
      setBooting(false);
    })();
  }, []);

  const onLogin = ({ accessToken, user }) => {
    setAccessToken(accessToken);
    setSession(user);
    setView(user.role === "admin" && view === "soc-login" ? "soc" : "storefront");
  };

  const onLogout = async () => {
    try { await api.logout(); } catch { /* best effort */ }
    setAccessToken(null);
    setSession(null);
    setView(session?.role === "admin" ? "soc-login" : "storefront");
  };

  const onBlocked = (verdict) => {
    setDenied({ type: verdict.type, alertId: verdict.alertId });
    setView("denied");
  };

  if (booting) {
    return <div className="center" style={{ marginTop: 120 }}><ShieldIcon size={32} /><p className="muted">Loading Aegis…</p></div>;
  }
  if (view === "denied") {
    return <AccessDenied type={denied.type} alertId={denied.alertId} onBack={() => setView("storefront")} />;
  }

  return (
    <div>
      <div className="topbar">
        <div className="brand"><ShieldIcon /> Aegis Security Platform</div>
        <div className="spacer" />
        <button className={`tab ${view === "soc" || view === "soc-login" ? "active" : ""}`} onClick={() => setView(session?.role === "admin" ? "soc" : "soc-login")}>SOC Console</button>
        <button className={`tab ${view === "storefront" ? "active" : ""}`} onClick={() => setView("storefront")}>Demo Storefront</button>
        <button className={`tab ${view === "simulator" ? "active" : ""}`} onClick={() => setView("simulator")}>Attack Simulator</button>
        {session?.role === "admin" && view === "soc" && (
          <button className="btn btn-red btn-sm" onClick={onLogout}>Log Out ({session.name})</button>
        )}
      </div>

      {view === "soc-login" && <SocLogin onLogin={onLogin} />}
      {view === "soc" && session?.role === "admin" && (
        <SocConsole user={session} onLogout={onLogout} focusAlert={focusAlert} />
      )}
      {view === "storefront" && (
        <Storefront
          session={session?.role === "admin" ? null : session}
          onLogin={onLogin}
          onLogout={onLogout}
          onBlocked={onBlocked}
        />
      )}
      {view === "simulator" && (
        <Simulator onViewAlert={(id) => {
          setFocusAlert(id);
          setView(session?.role === "admin" ? "soc" : "soc-login");
        }} />
      )}
    </div>
  );
}

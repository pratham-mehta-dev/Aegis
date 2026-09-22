import React from "react";
import { ShieldIcon } from "../components/ui.jsx";

export default function AccessDenied({ type, alertId, onBack }) {
  return (
    <div className="denied">
      <div className="panel">
        <div className="row"><ShieldIcon size={28} /><h1>403</h1></div>
        <h2 className="mt8">Request Blocked by Aegis</h2>
        <p className="muted mt8">
          The Application Layer Engine classified this request as{" "}
          <b style={{ color: "#f2994a" }}>{type || "malicious"}</b> and blocked it
          before it reached the application.
        </p>
        <div className="detail-item mt16">
          <div className="k">Reference ID</div>
          <div className="mono">{alertId || "n/a"} &middot; {new Date().toLocaleString()}</div>
        </div>
        <button className="btn mt16" onClick={onBack}>&larr; Back to site</button>
      </div>
    </div>
  );
}

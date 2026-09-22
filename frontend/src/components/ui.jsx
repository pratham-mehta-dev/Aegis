import React from "react";

export const SEV_CLASS = {
  Critical: "sev-critical",
  High: "sev-high",
  Medium: "sev-medium",
  Low: "sev-low",
};

export function Badge({ text, kind }) {
  const cls = SEV_CLASS[text] || `status-${kind || text}`;
  return <span className={`badge ${cls}`}>{text}</span>;
}

export function Kpi({ label, value, color }) {
  return (
    <div className="kpi" style={{ borderLeftColor: color }}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value">{value}</div>
    </div>
  );
}

export function Modal({ children, onClose }) {
  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        {children}
      </div>
    </div>
  );
}

export function Toast({ text }) {
  return text ? <div className="toast">{text}</div> : null;
}

export function Msg({ kind, children }) {
  return children ? <div className={`msg msg-${kind}`}>{children}</div> : null;
}

export function Field({ label, children }) {
  return (
    <label className="field">
      {label}
      {children}
    </label>
  );
}

export const fmtTime = (ms) => new Date(ms).toLocaleString();

export const ShieldIcon = ({ size = 18 }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

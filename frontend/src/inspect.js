import { api } from "./api.js";

// Local heuristic used only when the ML service is unreachable (FR-D3).
const LOCAL_SQLI = /(\bunion\b[\s\S]*\bselect\b)|('|")\s*or\s*'?[\w'"]+\s*=\s*'?\w+|--|\bdrop\s+table\b|\bsleep\s*\(|\bor\s+1\s*=\s*1/i;
const LOCAL_XSS = /<\s*(script|img|svg|iframe|body)\b|on\w+\s*=\s*['"]?\w+\(|javascript:/i;

export async function inspectPayload(payload) {
  try {
    return await api.predict({ payload, endpoint: "storefront" });
  } catch (err) {
    if (err.status === 503) {
      const type = LOCAL_SQLI.test(payload) ? "SQL Injection" : LOCAL_XSS.test(payload) ? "XSS" : "Benign";
      return {
        malicious: type !== "Benign",
        type,
        confidence: 0.5,
        severity: { "SQL Injection": "Critical", XSS: "Medium", Benign: "Low" }[type],
        model: "local-regex-fallback",
        alertId: null,
      };
    }
    if (err.status === 403 && err.data?.blocked) {
      return { malicious: true, type: "Blocked Source", severity: "High", alertId: null };
    }
    throw err;
  }
}

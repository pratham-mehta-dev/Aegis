// All backend calls go through here. Access token lives in memory only;
// the refresh cookie is httpOnlby and sent automatically (same origin / CORS credentials).

let accessToken = null;
let onSessionExpired = null;

export const setAccessToken = (t) => { accessToken = t; };
export const getAccessToken = () => accessToken;
export const setSessionExpiredHandler = (fn) => { onSessionExpired = fn; };

async function request(path, { method = "GET", body, auth = true } = {}) {
  const headers = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (auth && accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const res = await fetch(path, {
    method,
    headers,
    credentials: "include",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401 && auth && accessToken) {
    // Try a single silent refresh before giving up.
    const ok = await tryRefresh();
    if (ok) return request(path, { method, body, auth });
    if (onSessionExpired) onSessionExpired();
  }
  let data = null;
  try { data = await res.json(); } catch { /* non-JSON */ }
  if (!res.ok) throw Object.assign(new Error(data?.error || `Request failed (${res.status})`), { status: res.status, data });
  return data;
}

export async function tryRefresh() {
  try {
    const res = await fetch("/api/auth/refresh", { method: "POST", credentials: "include" });
    if (!res.ok) return false;
    const data = await res.json();
    accessToken = data.accessToken;
    return data.user || true;
  } catch {
    return false;
  }
}

export const api = {
  googleStatus: () => request("/api/auth/google/status", { auth: false }),
  googlePending: () => request("/api/auth/google/pending", { auth: false }),
  register: (b) => request("/api/auth/register", { method: "POST", body: b, auth: false }),
  login: (b) => request("/api/auth/login", { method: "POST", body: b, auth: false }),
  verify2fa: (b) => request("/api/auth/2fa/verify", { method: "POST", body: b, auth: false }),
  resend2fa: (b) => request("/api/auth/2fa/resend", { method: "POST", body: b, auth: false }),
  resendVerification: (b) => request("/api/auth/resend-verification", { method: "POST", body: b, auth: false }),
  forgotPassword: (b) => request("/api/auth/forgot-password", { method: "POST", body: b, auth: false }),
  resetVerifyOtp: (b) => request("/api/auth/reset-password/verify-otp", { method: "POST", body: b, auth: false }),
  resetPassword: (b) => request("/api/auth/reset-password", { method: "POST", body: b, auth: false }),
  logout: () => request("/api/auth/logout", { method: "POST", auth: false }),
  me: () => request("/api/auth/me"),

  predict: (b) => request("/api/ids/predict", { method: "POST", body: b, auth: false }),
  simulate: (b) => request("/api/ids/simulate", { method: "POST", body: b }),

  totpSetup: () => request("/api/auth/2fa/totp/setup", { method: "POST" }),
  totpConfirm: (b) => request("/api/auth/2fa/totp/confirm", { method: "POST", body: b }),
  useEmail2fa: () => request("/api/auth/2fa/method/email", { method: "POST" }),

  adminAlerts: (qs) => request(`/api/admin/alerts${qs ? `?${qs}` : ""}`),
  adminAlert: (id) => request(`/api/admin/alerts/${id}`),
  adminPatchAlert: (id, action) => request(`/api/admin/alerts/${id}`, { method: "PATCH", body: { action } }),
  adminBlocklist: () => request("/api/admin/blocklist"),
  adminBlock: (b) => request("/api/admin/blocklist", { method: "POST", body: b }),
  adminUnblock: (ip) => request(`/api/admin/blocklist/${encodeURIComponent(ip)}`, { method: "DELETE" }),
  adminStats: () => request("/api/admin/stats"),
  adminUsers: () => request("/api/admin/users"),
  adminAudit: () => request("/api/admin/audit"),
  modelInfo: () => request("/api/model/info"),
};

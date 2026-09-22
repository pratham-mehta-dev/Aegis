# Aegis — AI-driven multi-layer IDPS (prototype)

A working prototype of an intrusion-detection-and-prevention demo:

- **Application Layer** — a Flask + scikit-learn service classifies request payloads
  (Benign / SQL Injection / XSS / Port Scan / DoS Flood / Brute Force).
- **Network Layer** — *simulated* (no packet capture); the Attack Simulator writes
  clearly-labelled simulated alerts.
- **SOC Console** — admin dashboard (KPIs, live alert feed, triage actions, IP
  blocklist with real server-side enforcement, CSV export, real model metadata).
- **Secure accounts** — register + Gmail verification, mandatory 2FA (email OTP or
  TOTP), lockout, rotating refresh sessions, OTP password reset, audit log.
- **Demo Storefront** — deliberately-vulnerable target app; non-credential inputs
  are inspected by the ML engine before processing.

## Layout

| Path | What |
|------|------|
| `server.js` | Express bootstrap: env validation, CORS allow-list, static frontend, error handler |
| `auth.js` | `/api/auth/*` — register/verify/login/2FA/refresh/logout/reset/TOTP |
| `ids.js` | `/api/ids/*` — ML proxy + alert persistence + blocklist enforcement |
| `admin.js` | `/api/admin/*` — alerts, blocklist, stats, audit, CSV export (admin-only) |
| `db.js` | SQLite schema (users, refresh_tokens, otp_codes, audit_log, alerts, blocked_ips) |
| `mailer.js` | SMTP mailer with dev console fallback + HTML escaping |
| `middleware/` | requireAuth, requireRole, rate limiters, asyncHandler |
| `scripts/create-admin.js` | Admin creation CLI |
| `ml_service/` | Flask ML service (toy model — see its README) |
| `frontend/` | Vite + React app (storefront, SOC console, simulator) |
| `docs/` | Original project docs (prd, architecture, design, rules, phases, memory) |

## Quick start

Requires **Node ≥ 22.5** (`node:sqlite`) and **Python 3** with pip.

```bash
# 1. Backend deps + config
npm install
cp .env.example .env
# generate the two required secrets and paste them into .env:
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"   # JWT_ACCESS_SECRET
node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"   # PENDING_2FA_SECRET

# 2. ML service
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r ml_service/requirements.txt
python ml_service/app.py                              # :5000, loopback

# 3. Frontend (build once; the API then serves it on :4000)
cd frontend && npm install && npm run build && cd ..

# 4. Run the API
npm run dev                                           # :4000

# 5. Create an admin (pre-verified; 2FA still mandatory at login)
npm run create-admin -- "Admin" admin@gmail.com 'StrongPass1!'
```

Open http://localhost:4000 — **Demo Storefront** for the customer flow,
**SOC Console** for the admin login, **Attack Simulator** to generate detections.

### Mail in dev

Without `SMTP_HOST`, emails are printed to the API console and appended to
`data/outbox.log` (verification links and OTP codes are readable there). Configure
SMTP (e.g. a Gmail app password) in `.env` for real delivery.

### Dev-mode frontend (optional)

`cd frontend && npm run dev` runs Vite on :5173 with an `/api` proxy to :4000.

## Security notes

- bcrypt cost 12; OTPs, refresh tokens, email-verify and reset tokens are SHA-256
  hashed at rest; two separate JWT secrets (access vs pending-2FA).
- Mandatory 2FA for every account; lockout 5 fails / 15 min; per-IP rate limits on
  login, OTP, reset, register and `/api/ids/predict`.
- Admin APIs are gated server-side by `requireAuth` + `requireRole("admin")`.
- Passwords are never sent to the IDS or stored in alerts.
- See `docs/rules.md` §3 for the full checklist applied to every endpoint.

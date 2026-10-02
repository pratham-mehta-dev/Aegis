# Phases: Roadmap and Progress

**Legend:** ✅ done · 🔄 in progress / partial · ⏳ planned · `[PROPOSED]` = suggested by this documentation, not confirmed by the owner.
Issue IDs (I-xx) refer to the known-issues list in `memory.md`. Feature IDs (FR-xx) refer to `prd.md`.

## Timeline of what already exists (from file timestamps)

| Date (2026) | Evidence |
|-------------|----------|
| 22 Aug | First interactive prototype (`idps_prototype.zip`: static React bundle, mock logins only) |
| 25 Aug | `files.zip` snapshot of the mock-only UI (13:42); then backend, DB, mailer, middleware, ML service and `.env.example` (~16:57-19:02) |
| 26 Aug | `auth.js` last edited (12:15); JSX rewired to the real backend and IDS proxy (12:36) |
| 27 Aug | `idps_prototype.html` rebuilt with a real-auth overlay (03:28): the most recent change in the project |

## Phase overview

| # | Phase | Status |
|---|-------|--------|
| 0 | Concept and UI prototype | ✅ Complete |
| 1 | Authentication backend | ✅ Complete |
| 2 | ML detection service (demo) | ✅ Complete |
| 3 | Frontend <-> backend integration | ✅ Complete |
| 4 | Stabilise and harden | ✅ Complete |
| 5 | Complete user auth journeys in the UI | ✅ Complete |
| 6 | Alerts backend, persistence and admin API | ✅ Complete |
| 7 | Real ML for the application layer | ✅ Complete |
| 8 | Network layer detection (Suricata sensor + gateway sync) | ✅ Complete |
| 9 | Quality, packaging and release (Docker + full test suite) | ✅ Complete |

---

## Phase 0: Concept and UI prototype ✅
**Goal:** show the two-layer IDPS idea visually.
- [x] SOC Console wireframes as a React prototype (Overview, Alerts, Blocked Sources & Reports, Model Settings)
- [x] Demo Storefront (login, reviews) and Attack Simulator
- [x] 403 "Request Blocked" experience
- [x] Design tokens (navy/blue palette, severity colours)

## Phase 1: Authentication backend ✅
**Goal:** secure accounts for customers and admins.
- [x] Express app, CORS allow-list, JSON limit, health check (`server.js`)
- [x] SQLite schema with users, refresh tokens, OTPs, audit log (`db.js`)
- [x] Register + email verification + resend (FR-A1..A3)
- [x] Login with lockout, mandatory 2FA (email OTP / TOTP), pending-2FA token (FR-A4, A5)
- [x] Access token + rotating refresh cookie, logout (FR-A7)
- [x] Forgot/reset password (OTP-based), session revocation (FR-A9 backend)
- [x] TOTP setup/confirm and method switch (FR-A8 backend)
- [x] Rate limiters (FR-A6) and audit logging (FR-A10)
- [x] Admin creation CLI (`npm run create-admin`)

## Phase 2: ML detection service (demo) ✅
**Goal:** prove the "AI classifies the payload" loop.
- [x] Flask service with `/health` and `/predict`
- [x] TF-IDF + Logistic Regression on 15 samples, 6 classes, severity map (FR-D1, D2)
- [x] Node proxy `POST /api/ids/predict` with 503 fallback (FR-D1)
- [x] Frontend regex fallback when ML is offline (FR-D3)

## Phase 3: Frontend <-> backend integration 🔄
**Goal:** replace mock logins with the real API.

**JSX build (26 Aug)**
- [x] Storefront: register, login, forgot-password *request*, 2FA code entry (FR-U1 partly)
- [x] Admin login with real backend and role gate in the browser (FR-S1 partly)
- [x] Storefront login/comment inputs inspected by ML, with regex fallback (FR-U2)
- [ ] Access token discarded after 2FA: no session, refresh or logout
- [ ] No OTP-entry / new-password screens (helper text still says "reset link", I-05)

**HTML build (27 Aug, newest file):** older compiled React prototype + vanilla-JS overlay
- [x] Real register panel, login + OTP panel (email or authenticator code), full 3-step forgot-password (email -> OTP -> new password), logout, user home and admin home (FR-U1, FR-A9 UI)
- [ ] No `/api/ids/predict` calls: login and reviews are not inspected; attack hints hidden
- [ ] Admin lands on a placeholder page: SOC Console, Attack Simulator and 403 screen are unreachable
- [ ] Never calls `/refresh`: reloading the page logs the user out

**Both**
- [ ] SOC Console still uses mock alerts/blocklist/KPIs
- [ ] The two builds diverge (I-09, I-18)

*Remaining items are absorbed into Phases 5 and 6.*

---

## Phase 4: Stabilise and harden `[PROPOSED]` ⏳ (do first)
**Goal:** nothing crashes; no obvious security gaps; repository is safe to share.
**Why first:** cheap, high impact, unblocks everything else.

- [ ] **I-01** Wrap all mail/network awaits in `try/catch` (`/login`, `/forgot-password`, `/resend-verification`, `/reset-password`); add an async-handler wrapper or `express-async-errors`; add a `process.on("unhandledRejection")` logger
- [ ] **I-02** Rotate `JWT_ACCESS_SECRET`, `PENDING_2FA_SECRET`, SMTP password if the zip was shared; add `.venv/` and `*.zip` to `.gitignore`
- [ ] **I-04** Add a limiter (and optionally auth or an API key) to `POST /api/ids/predict`; cap payload length
- [ ] **I-06** Enforce the registration password policy on reset
- [ ] **I-10** Escape `name` in HTML emails
- [ ] **I-11** Hash email-verify and reset tokens (SHA-256) like OTPs; consider encrypting `totp_secret`
- [ ] **I-13** Remove the hardcoded Windows `FRONTEND_URL` fallback; require/validate the env var
- [ ] Add `requireRole` middleware (prerequisite for Phase 6)
- [ ] Add a scheduled cleanup for expired OTP/refresh rows

**Done when:** simulating SMTP failure on every email route leaves the server running with a clean error response; security checklist in `rules.md` section 3 passes for all existing routes.

## Phase 5: Complete user auth journeys in the UI `[PROPOSED]` ⏳
**Goal:** there is **one** frontend, and every backend auth feature is usable from it. (FR-A3, A7, A8, A9, U1)

- [ ] **Consolidate the two frontends (I-09, I-18):** create one Vite + React app that merges the JSX (SOC Console, Attack Simulator, ML checks, 403 view) with the flows that currently exist only in the HTML overlay (create-account, OTP panel, 3-step forgot-password, logout, user/admin homes); then delete the overlay and the stale archives
- [ ] Keep the access token in memory; call `/refresh` on load; show signed-in state; keep **Logout** (already in the HTML overlay)
- [ ] Forgot-password flow: **port** the 3-step flow from the HTML overlay into React (email -> OTP -> new password) and fix the JSX wording "reset link" (I-05)
- [ ] Resend-verification and resend-2FA-code buttons
- [ ] Account/security page: enable authenticator app (QR from `/2fa/totp/setup`, confirm code), switch back to email OTP
- [ ] Don't send credentials to the IDS or store them in alerts (I-07)
- [ ] Accessibility pass on forms (D-1, D-2 in `design.md`)
- [ ] Decide and document: remove the leftover link-based reset page and unused `sendPasswordResetEmail` (I-15), or use them

**Done when:** a new user can register, verify, log in with 2FA, enrol TOTP, log out, and recover a forgotten password entirely from the UI.

## Phase 6: Alerts backend, persistence and admin API `[PROPOSED]` ⏳
**Goal:** the SOC Console shows real, persistent data. (FR-S1..S7, FR-D6, FR-A11, A12)

- [ ] New tables `alerts` and `blocked_ips` (+ indexes) in `db.js`; document in `architecture.md`
- [ ] Persist every `/api/ids/predict` verdict as an alert (with real client IP from `req.ip`, endpoint, payload with credentials redacted, model name/version)
- [ ] Admin-only API (`requireAuth` + `requireRole("admin")`): `GET /api/alerts` (filters, pagination), `GET /api/alerts/:id`, `PATCH /api/alerts/:id` (confirm / false positive), `GET/POST/DELETE /api/blocklist`, `GET /api/stats` (KPIs)
- [ ] Enforce the blocklist server-side (reject blocked IPs before ML)
- [ ] Real CSV export (and optional PDF)
- [ ] Optional: audit-log viewer and "disable account" action for admins
- [ ] Replace mock data in `SocConsole`; delete hardcoded "Signed in as" and accuracy KPIs (I-03, I-08)
- [ ] Live updates via polling or Server-Sent Events

**Done when:** alerts and blocklist survive restart and refresh, a non-admin token gets 403 from every admin route, and no KPI is hardcoded.

## Phase 7: Real ML for the application layer `[PROPOSED]` ⏳
**Goal:** trustworthy detection with measured quality. (FR-D4)

- [ ] Choose and document a dataset (SQLi/XSS/benign) with licence, size and class balance
- [ ] Training script separate from the service; train/validation/test split; report precision, recall, F1 per class and a confusion matrix
- [ ] Save/load the model (`joblib`) with a version string; expose it in `/health` and in alerts
- [ ] Feature improvements (char n-grams, normalisation/decoding of URL/HTML encodings), consider tree/boosting models; compare against baseline
- [ ] Threshold tuning and false-positive review workflow feeding back into training data
- [ ] Update "Model Settings" UI with real metrics and an actual retrain endpoint (admin-only) or remove the button (I-08)
- [ ] Unit tests for the classifier with known samples

**Done when:** README/UI quote only metrics produced by committed code on held-out data.

## Phase 8: Network layer detection `[PROPOSED]` ⏳ (needs owner decision)
**Goal:** replace the simulator with real network-layer detection, or formally keep it as a simulation.

- [ ] **Decision:** real vs simulated (open question in `memory.md`)
- If real:
  - [ ] Pick a dataset (UI mentions CICIDS2017) and a traffic/flow feature pipeline
  - [ ] Train/evaluate a flow classifier (e.g. Random Forest / XGBoost) for Port Scan, DoS, Brute Force
  - [ ] Ingestion: PCAP replay or flow-log import (avoid live capture unless legally/technically safe)
  - [ ] Separate detector service; write alerts to the same `alerts` table with `layer = "Network"`
  - [ ] Blocking action (simulated firewall rule or integration point)
- If simulated:
  - [ ] Label network alerts as "simulated" in the UI and docs; keep the Attack Simulator as a demo tool

## Phase 9: Quality, packaging and release `[PROPOSED]` ⏳
**Goal:** repeatable, testable, presentable.

- [ ] Backend tests with `node:test` (auth flows incl. lockout, OTP attempts, refresh rotation, reset); ML tests with `pytest`; `npm test` script
- [ ] Split the consolidated frontend into components, add UI tests (Vitest / Playwright), and remove stale archives (`files.zip`, `files/idps_prototype.zip`)
- [ ] Environment validation on startup with clear messages
- [ ] Docker Compose (api, ml, frontend) and a `README` quick start that works on a clean machine
- [ ] CI (lint, tests); optional switch from `node:sqlite` to a stable driver if needed
- [ ] Final documentation pass (`prd.md`, `architecture.md`, `design.md`), demo script and screenshots

---

## Current focus
**Phase 4**, starting with I-01 (crash risk) and I-02 (secrets hygiene). Update this section and `memory.md` after each session.

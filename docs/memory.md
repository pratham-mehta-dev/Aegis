# Memory: Aegis Project (living document)

> **Purpose:** the first file an AI should read and the last one it should update. It holds current state, decisions, known issues, gotchas and open questions so no session starts from zero.
> **Rule:** keep it short, factual and current. Never store secrets or user data here (key **names** only).

- **Created:** 2026-09-21 (reverse-engineered from the owner's `project.zip`)
- **Last updated:** 2026-09-21 (second pass: every nested zip and the HTML's second script were re-read; frontend description corrected)
- **Read next:** `phases.md` (what to do), `architecture.md` (how it works), `rules.md` (how to behave), `prd.md` (why), `design.md` (UI)

## 1. Project snapshot

**Aegis** = prototype **AI-driven multi-layer IDPS** (intrusion detection & prevention). Three parts:

| Part | Tech | Reality |
|------|------|---------|
| Auth backend | Node >= 22.5, Express 4, `node:sqlite`, bcryptjs, JWT, otplib, nodemailer | **Real, largely complete** |
| ML service | Flask + scikit-learn (TF-IDF + LogisticRegression, 15 hardcoded samples) | Works, **toy** |
| Frontend | **Two diverging builds** (I-09). (a) `files/idps_frontend_prototype.jsx` (26 Aug): ML/IDS checks, SOC Console (mock data), Attack Simulator, 403 screen, real login/register/2FA. (b) `files/idps_prototype.html` (27 Aug, **newest file in the project**): older compiled React prototype + hand-written JS overlay adding real register, login+OTP, full 3-step password reset, logout, user and admin home pages, but **no ML/IDS calls** | UI prototype; SOC data is **mock**; neither build has every feature |

**Simulated (not real):** network-layer detection, alerts list, blocklist, KPI/model-accuracy cards, admin authorization (browser-only check).
**Dev environment:** Windows, PowerShell, local only. Ports: Unified server on 4001 (serves frontend SPA + API), ML 5000 (loopback).

## 2. Current focus and next actions

- **Current phase:** 4 (Stabilise and harden), see `phases.md`.
- **Next actions, in order:**
  1. Fix I-01: wrap mail sends in `try/catch` / add async wrapper so SMTP failure can't crash the API.
  2. Fix I-02: rotate secrets if the zip was shared; add `.venv/` to `.gitignore`.
  3. Add limiter to `/api/ids/predict` (I-04) and `requireRole` middleware (prerequisite for admin APIs).
  4. Phase 5, step 1: decide how to merge the two frontends (I-09); then finish the UI auth journeys; then Phase 6 (alerts persistence).
- **Blocked on owner:** see section 8 (open questions).

## 3. Recent changes (newest first)

| Date | Change | By |
|------|--------|----|
| 2026-09-21 | **Second pass:** re-read `files.zip`, the nested prototype zip and the HTML's second `<script>`. Corrected earlier docs: the HTML build is the newest file and has real auth flows; the two frontends diverge (I-09, I-18). **No source code modified** | AI (Claude) |
| 2026-09-21 | Generated `prd.md`, `architecture.md`, `rules.md`, `design.md`, `phases.md`, `memory.md` from `project.zip`. **No source code was modified** | AI (Claude) |
| 2026-08-27 03:28 | `files/idps_prototype.html` rebuilt with the real-auth overlay: latest change in the project (from file mtime) | owner |
| 2026-08-26 12:36 | `files/idps_frontend_prototype.jsx` integrates real backend + IDS proxy (mtime) | owner |
| 2026-08-26 12:15 | Last edit to `auth.js` (mtime) | owner |
| 2026-08-25 | Backend (`db.js`, `middleware/`, `utils/`, `scripts/`, `mailer.js`, `server.js`), ML service, `.env` created between ~16:57 and 19:02; `files.zip` snapshot of the mock-only UI at 13:42 (mtimes) | owner |
| 2026-08-22 | First static prototype (`idps_prototype.zip`) | owner |

*Append a row for every work session.*

## 4. Decisions log (inferred from code unless noted)

| ID | Decision | Rationale **[ASSUMPTION]** | Change only with owner approval |
|----|----------|----------------------------|---|
| D-001 | 2FA is **mandatory** for every account (user and admin); `two_fa_enabled` is always 1 | Security-first demo | Yes |
| D-002 | Two 2FA methods: email OTP (default) or TOTP | Simple default + stronger option | Yes |
| D-003 | Access JWT 15 min + **rotating** refresh token in httpOnly cookie (path `/api/auth`) | Limits token theft impact | Yes |
| D-004 | Separate secrets for access token and "pending 2FA" token | Prevent token confusion | Yes |
| D-005 | Built-in `node:sqlite` (no native module, single file DB) | Easy Windows setup | No |
| D-006 | Raw SQL, no ORM; no migrations | Small project | No |
| D-007 | Registration limited to `@gmail.com` (frontend + backend) | Demo simplification / valid mailbox | Ask |
| D-008 | Admins are created only via CLI (`create-admin`), pre-verified | Avoid self-service admin | Yes |
| D-009 | ML runs as a separate Flask process behind a Node proxy; loopback only | Language fit (Python ML) | No |
| D-010 | Frontend falls back to regex detection if ML is offline | Keep demo usable | No |
| D-011 | Email OTP is the current password-reset method (replacing an older link-based design) | Simpler UX | Ask |
| D-012 | Storefront is *deliberately vulnerable*; every input passes through the IDS first | Demo narrative | Yes |
| D-013 | Password is verified before the "email not verified" check | Simpler flow (leaks verified-status only to someone with the password) | No |

## 5. Known issues (IDs are referenced from other files)

| ID | Sev | Issue | Where |
|----|-----|-------|-------|
| I-01 | **High** | `await mailer...` without `try/catch` in `/login`, `/forgot-password`, `/resend-verification`, `/reset-password`: Express 4 won't catch it, SMTP failure can crash the process. (`/register`, `/2fa/resend` are safe) | `auth.js` |
| I-02 | **High** | The shared zip contained `.env`, `data/auth.sqlite` (8 users, ~84 audit rows) and `.venv/`. `.gitignore` lacks `.venv/` and `*.zip`. Rotate `JWT_ACCESS_SECRET`, `PENDING_2FA_SECRET`, SMTP password if the zip was shared | repo hygiene |
| I-03 | **High** | Admin authorization exists only in the browser; `requireAuth` doesn't check role; no admin API yet | `middleware/auth.js`, JSX |
| I-04 | Med | `POST /api/ids/predict` public and un-rate-limited | `server.js` |
| I-05 | Med | **JSX build only:** password reset half-built: helper text says "reset link" although the backend sends an OTP, and the JSX never calls `reset-password/verify-otp` or `reset-password`. (The HTML build implements all three steps with correct "OTP" wording.) The OTP email itself says "login code" | JSX, `mailer.js` |
| I-06 | Med | Reset accepts any password >= 8 chars (register requires upper/lower/digit/special) | `auth.js` |
| I-07 | Med | Login form sends `username + " " + password` to the IDS; on a block the alert payload (`username \|\| password`) is displayed in the SOC console | JSX |
| I-08 | Med | UI placeholders contradict reality: "XGBoost/RandomForest", CICIDS2017, 94.8/97.1/96.4% accuracy, "Retrain Model", "admin@company.com" | JSX |
| I-09 | Med | **Two diverging frontends.** JSX: IDS/ML checks, SOC Console, Attack Simulator, 403 screen; no reset screens, no logout. HTML: real auth journeys via a DOM-patching overlay; **no `/api/ids/predict` calls**, attack hints hidden, admins land on a placeholder page (SOC Console and Simulator unreachable after real login). Neither has everything. The backend's fallback "Return to sign in" link points at the HTML build | `files/` |
| I-10 | Low | Email HTML interpolates user-supplied `name` unescaped | `mailer.js` |
| I-11 | Low | Verify/reset tokens and TOTP secret stored unhashed/unencrypted | DB |
| I-12 | Low | `register` returns 409 for existing email (enumeration) | `auth.js` |
| I-13 | Low | Hardcoded fallback `file:///D:/Sem_4_Project/project/files/idps_prototype.html` for `FRONTEND_URL` | `auth.js` |
| I-14 | Low | In-memory rate-limit store; Flask dev server; experimental `node:sqlite`; expired OTP/refresh rows never purged; no migrations; SMTP transport built per email | misc |
| I-15 | Low | Vestigial: `two_fa_enabled` column, `mailer.sendPasswordResetEmail`, leftover `GET /reset-password` page | misc |
| I-16 | Med | ML model trained on 15 samples with no evaluation: `confidence` is not meaningful | `ml_service/app.py` |
| I-17 | Low | **JSX build:** discards the access token after 2FA (no session, refresh, logout). **HTML build:** has Logout (calls `/logout`, reloads) but never calls `/refresh`, so a page reload logs the user out | JSX / HTML |
| I-18 | Low | The HTML overlay is fragile: it finds elements by visible text (e.g. the "Sign In" button), uses a `MutationObserver` and capture-phase listeners to hijack the React app, and replaces `#root` with `innerHTML` after login (unmounting React). Treat it as a reference to port, not a base to extend | `files/idps_prototype.html` |

## 6. Gotchas and tribal knowledge

- **Node version matters:** `node:sqlite` needs Node >= 22.5 (early 22.x may require `--experimental-sqlite`).
- **Timestamps are epoch milliseconds**, not seconds. Booleans are 0/1.
- **Emails are stored lowercase**; always `.toLowerCase()` before lookups.
- **Files use CRLF** line endings (Windows); keep them when editing.
- **Refresh cookie is scoped to `/api/auth`** and `sameSite=lax`, `secure` only when `NODE_ENV=production`. The frontend must send `credentials: "include"`; cross-origin dev works only because CORS allows credentials for allow-listed origins.
- **CORS:** `null` origin (pages opened via `file://`) is allowed only when `NODE_ENV !== "production"`.
- **OTP verification uses the latest unconsumed code** for the user+purpose; generating a new one supersedes the older.
- **`/api/auth/2fa/totp/setup` overwrites `totp_secret` immediately**, even if the user never confirms (the login method only switches after `confirm`; but a user already on TOTP who re-runs setup and abandons it would break their own TOTP login).
- **Login `lockout` is checked before the password**; wrong passwords after lock don't extend it.
- **The ML model retrains on every start** (tiny dataset, so it is quick); labels/severity are in `ml_service/app.py`.
- **Source IPs in UI alerts are fake** (`203.0.113.x` documentation range, `198.51.100.x`, `192.168.1.x`).
- **Attack "blocking" is cosmetic:** nothing is blocked server-side.
- **Two frontends diverge;** decide which one you are editing (I-09). Don't add features to the HTML overlay: port its flows into React components. The React code *inside* the HTML is the older mock prototype (hardcoded demo logins) and is neutralised by the overlay, which intercepts the "Sign In" click.
- **`files.zip` and `files/idps_prototype.zip` are stale snapshots** (mock-only UI, 25 Aug and 22 Aug content). Ignore them; the loose files in `files/` are current.
- **`.env` exists in the archive;** never print it. Its keys are listed in `architecture.md` section 8.

## 7. Commands cheat sheet (PowerShell)

```powershell
npm install
copy .env.example .env                       # then fill values
npm run create-admin -- "Name" you@gmail.com StrongPass1!
npm run dev                                  # API :4001 (auto-restart)
npm start                                    # API :4001 without watch

python -m venv .venv ; .venv\Scripts\activate
pip install -r ml_service/requirements.txt
npm run ml                                   # ML :5000

curl http://localhost:4001/health
curl -X POST http://localhost:4001/api/ids/predict -H "Content-Type: application/json" -d "{\"payload\":\"' OR '1'='1' --\"}"
```

Demo inputs for detection: `' OR '1'='1' --`, `union select username password from users`, `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`.

## 8. Open questions (owner to answer, then move to Decisions)

1. What is the exact goal/deliverable (course project? report/"SAD" document? demo day?) and the deadline?
2. Will the **network layer** be real? If yes, which dataset (UI mentions CICIDS2017) and what ingestion (PCAP / flow logs)?
3. Is **Gmail-only** registration a requirement or a shortcut?
4. Should password reset be **OTP** (current) or **link** (older page)?
5. Final deployment target: local only, or hosted?
6. Frontend direction: which build do you actually demo (JSX with IDS, or HTML with real auth flows)? Merge both into one Vite + React app?
7. Was `project.zip` (with `.env` and the DB) shared outside your machine? (drives I-02 urgency)
8. Where is the "SAD report" the UI refers to? Sharing it would let `prd.md` and `design.md` be confirmed instead of inferred.

## 9. Glossary

| Term | Meaning |
|------|---------|
| IDPS / IDS | Intrusion Detection (and Prevention) System |
| SOC | Security Operations Center, the analyst-facing console |
| SQLi / XSS | SQL injection / cross-site scripting |
| Application layer / Network layer | Detection of malicious *payloads* vs malicious *traffic patterns* |
| OTP | One-time password (6 digits, emailed) |
| TOTP | Time-based OTP from an authenticator app (30 s step, window 1) |
| Pending token | Short-lived JWT proving step 1 (password) of login passed |
| Refresh token | Long-lived, rotating session token in an httpOnly cookie |
| SAD | Presumably "System Analysis and Design" report **[ASSUMPTION]** |
| Alert | Detection record shown in the SOC Console (currently client-side only) |

## 10. How to update this file

At the end of every session:
1. Add a row to **Recent changes**; update **Current focus and next actions**.
2. Add/close items in **Known issues** (keep IDs stable; mark fixed items `FIXED yyyy-mm-dd` instead of deleting).
3. Record any new **Decision** (ID, rationale) and move answered **Open questions** into it.
4. Update `phases.md` checkboxes and, if contracts/screens changed, `architecture.md` / `design.md`.
5. Re-check that no secrets or user data were written into any doc.

## Session 2026-09-22 (rebuild)

**Full project rebuilt from docs only** (original source was not in the zip). One consolidated
Vite + React app replaces both diverging frontends (I-09, I-18 FIXED). New `alerts` + `blocked_ips`
tables; every `/api/ids/predict` verdict is persisted (FR-D6); admin API (`/api/admin/*`) gated
server-side via `requireAuth` + `requireRole("admin")` (I-03 FIXED). Fixed: I-01 (asyncHandler +
process handlers), I-04 (idsLimiter on predict), I-05 (OTP wording), I-06 (reset enforces policy),
I-07 (passwords never sent to IDS), I-08 (model tab shows real `/api/model/info`), I-10 (email
escaping), I-11 (verify/reset tokens SHA-256 hashed), I-13 (FRONTEND_URL required, no hardcoded
path), I-14 (hourly purge of expired rows), I-17 (refresh-on-load + logout in UI).

**Added:** `/api/ids/simulate` (labelled simulated network-layer alerts), `/api/model/info`
(admin), CSV export (real), audit entries for admin mutations, `tests/api.test.js` (10 passing),
mail dev mode (emails to console + `data/outbox.log` when SMTP_HOST unset), `totp_pending_secret`
column (TOTP setup no longer breaks existing TOTP).

**Status:** Phases 0-6 complete for the app layer. Remaining: Phase 7 (real dataset/model),
Phase 8 (network layer decision), Phase 9 (Docker/CI).

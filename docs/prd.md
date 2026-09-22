# PRD: Aegis (AI-Driven Multi-Layer IDPS)

| | |
|---|---|
| **Document status** | Reverse-engineered from the codebase on 2026-09-21. Requirements marked **[ASSUMPTION]** are inferred, not confirmed by the owner |
| **Product stage** | Working prototype (student / academic project) |
| **Owner** | Project author (see `memory.md` open questions) |
| **Companion docs** | `architecture.md`, `design.md`, `rules.md`, `phases.md`, `memory.md` |

## 1. Problem and vision

Web applications are attacked through their inputs (SQL injection, XSS) and their network surface (port scans, floods, brute force). Traditional rule-based filters are brittle. **Aegis** explores an **AI-assisted, two-layer defence**: an *Application Layer* engine that classifies request payloads with machine learning, and a *Network Layer* engine for traffic-level attacks, surfaced to a security analyst through a **SOC (Security Operations Center) console**, with a secure account system protecting access. **[ASSUMPTION]**

**Vision (one line):** *Detect and block malicious web/network activity with ML, show it live to an analyst, and keep the platform itself locked down with strong authentication.*

## 2. Goals and non-goals

### Goals
1. Provide a **secure authentication system** (verified email, mandatory 2FA, session management, audit trail) for both customers and admins.
2. Classify incoming payloads as **Benign / SQL Injection / XSS / Port Scan / DoS Flood / Brute Force** with a severity and confidence score.
3. Present detections in a **SOC Console** (overview, alert list, alert detail, blocklist, reports, model info).
4. Demonstrate the product end-to-end with a **deliberately vulnerable demo storefront** and an **Attack Simulator**.

### Non-goals (current release)
- Real packet capture / inline network blocking (network layer is **simulated**).
- Production-grade detection accuracy (model is a demo trained on 15 samples).
- Multi-tenant SaaS, billing, or mobile apps.
- Real e-commerce (the "storefront" only exists to generate traffic for the IDS).

## 3. Users and personas

| Persona | Description | Main needs |
|---------|-------------|------------|
| **Security Admin / SOC Analyst** | Logs into the SOC Console with an admin account | See alerts in near-real-time, inspect payloads, confirm or mark false positives, block/unblock IPs, export reports, see model status |
| **Customer (end user)** | Registers and logs into the storefront | Easy, safe sign-up/sign-in; not be blocked when behaving normally |
| **Attacker (simulated)** | The presenter acting maliciously | Trigger visible detections (typing `' OR '1'='1`, `<script>`, launching simulated scans) **[ASSUMPTION]** |
| **Developer / Evaluator** | Owner, teacher, reviewer | Run locally, understand architecture, verify security claims |

## 4. Product scope: modules

| Module | Purpose | Release status |
|--------|---------|----------------|
| M1 Authentication & Accounts | Register, verify, login+2FA, sessions, reset | Backend done; UI partially wired |
| M2 Detection Engine (ML) | Classify payload text | Working demo, toy model |
| M3 SOC Console | Analyst dashboard | UI prototype with mock data |
| M4 Demo Storefront | User-facing target app | UI prototype; login/register real |
| M5 Attack Simulator | Generate demo detections | UI prototype (simulated) |

> **Two frontend builds exist and neither is complete.** The JSX build has the IDS experience (ML checks, SOC Console, Simulator, 403 page) but no password-reset screens or logout. The HTML build (newest) has the full account journeys via a JavaScript overlay but no IDS features and only a placeholder admin page. Merging them is the first task of Phase 5 (`phases.md`).

## 5. Functional requirements

Priority: **M** = must, **S** = should, **C** = could. Status: ✅ done, ⚠️ partial, ❌ not started.

### M1: Authentication & accounts
| ID | Requirement | Pri | Status |
|----|-------------|-----|--------|
| FR-A1 | Users register with name, email, password. Email must end in `@gmail.com`; password >= 8 chars with upper, lower, digit, special | M | ✅ |
| FR-A2 | Registration sends an email-verification link valid 30 min; login is blocked until verified | M | ✅ |
| FR-A3 | Users can request a new verification email (generic response) | S | ✅ backend, ❌ UI |
| FR-A4 | Login is two-step and **2FA is mandatory for every account**: password, then 6-digit email OTP (5 min) or authenticator-app TOTP | M | ✅ |
| FR-A5 | After 5 wrong passwords the account locks for 15 min and the owner is alerted by email | M | ✅ |
| FR-A6 | Rate-limit login, OTP, reset and registration endpoints per IP | M | ✅ |
| FR-A7 | Short-lived access token (15 min) + rotating httpOnly refresh cookie (7 days); logout revokes the session | M | ✅ backend; ⚠️ UI: HTML build has Logout, neither build refreshes on load |
| FR-A8 | Users can enrol an authenticator app and switch 2FA method | S | ✅ backend, ❌ UI |
| FR-A9 | Forgot-password: email OTP -> reset token -> new password; all sessions revoked; security-alert email | M | ✅ backend; ✅ UI in HTML build (3 steps); ⚠️ JSX build only requests the OTP |
| FR-A10 | Every security-relevant event is written to an audit log | M | ✅ (write-only) |
| FR-A11 | Admin accounts are created out-of-band via CLI; admin role gates the SOC Console | M | ⚠️ client-side gate only |
| FR-A12 | Admins can view the audit log / disable accounts through the product | C | ❌ |

### M2: Detection engine
| ID | Requirement | Pri | Status |
|----|-------------|-----|--------|
| FR-D1 | `POST /api/ids/predict` accepts text and returns `{malicious, type, confidence, severity, model}` | M | ✅ |
| FR-D2 | Classes: Benign, SQL Injection, XSS, Port Scan, DoS Flood, Brute Force with fixed severity mapping | M | ✅ |
| FR-D3 | If the ML service is down, the storefront falls back to a regex heuristic (SQLi/XSS only) | S | ✅ |
| FR-D4 | Model trained on a real labelled dataset with reported precision/recall on a held-out set | M (target) | ❌ |
| FR-D5 | Network-layer engine consuming traffic/flow features | S (target) | ❌ |
| FR-D6 | Every verdict is persisted as an alert | M (target) | ❌ |

### M3: SOC Console (admin)
| ID | Requirement | Pri | Status |
|----|-------------|-----|--------|
| FR-S1 | Admin-only login (real backend + 2FA); non-admins are rejected | M | ⚠️ JSX: real login then SOC Console; HTML: real login then a placeholder admin page; role check is browser-only |
| FR-S2 | **Overview:** KPI cards (total alerts, critical, blocked sources, model accuracy), live alert feed, attack-type distribution, severity heatmap | M | ⚠️ mock data |
| FR-S3 | **Alerts:** table with filters (layer, severity, source-IP search) and detail modal with raw payload | M | ⚠️ mock data |
| FR-S4 | Alert actions: *Confirm & Keep Blocked*, *Mark False Positive*, *Add to Blocklist* | M | ⚠️ client state only |
| FR-S5 | **Blocked Sources:** list, manual block, unblock; **Reports:** export CSV / PDF | S | ⚠️ UI only (export shows a toast) |
| FR-S6 | **Model Settings:** show model metadata; retrain button | C | ⚠️ static text, button does nothing |
| FR-S7 | Alerts, blocklist and KPIs come from the server and survive refresh | M (target) | ❌ |

### M4/M5: Demo storefront and Attack Simulator
| ID | Requirement | Pri | Status |
|----|-------------|-----|--------|
| FR-U1 | Storefront login/register/forgot/2FA forms call the real backend | M | ✅ HTML build (incl. reset + logout); ⚠️ JSX build (no reset step, no session) |
| FR-U2 | Login form input and the review box are inspected by the detection engine before processing | M | ✅ JSX build only; ❌ HTML build (no ML calls) |
| FR-U3 | A malicious input shows a full-screen "403 Request Blocked by Aegis" page with a reference ID and creates an alert | M | ✅ |
| FR-X1 | Simulator launches preset attacks (nmap port scan, hping3 flood, hydra brute force, SQLi, XSS, benign control) and links to the resulting alert | S | ✅ (simulated) |

## 6. Non-functional requirements

| Area | Requirement |
|------|-------------|
| **Security** | bcrypt (cost 12); OTPs/refresh tokens hashed at rest; separate JWT secrets; CORS allow-list; body limit 32 kb; no secrets in repo/docs; server-side authorization for every privileged action (**target**) |
| **Reliability** | A mail/DB/network failure must never crash the server (**currently violated**, see `memory.md` I-01) |
| **Performance** | **[ASSUMPTION/target]** verdict returned in < 300 ms locally; login flow < 1 s excluding email delivery |
| **Usability** | Clear error messages that do not reveal whether an account exists; forms validate before submit |
| **Portability** | Runs on Windows locally with Node >= 22.5 and Python 3.x; no external DB |
| **Maintainability** | Small single-purpose files, documented API and schema (`architecture.md`), rules in `rules.md` |
| **Privacy** | Store only name, email, password hash, 2FA secret; do not display or store credential text in alerts (**target**, see I-07) |

## 7. Key user stories and acceptance criteria

1. **Register and verify.** *As a customer I want to create an account so I can shop.*
   - Given a valid Gmail address and strong password, registration returns 201 and an email arrives with a link.
   - Given the link is opened within 30 min, the account is verified; after that, login proceeds to 2FA.
   - If the email cannot be sent, no account remains in the DB.
2. **Log in with 2FA.** *As a user I want a second factor so stolen passwords are not enough.*
   - Correct password yields a `pendingToken` and (for email method) an OTP; wrong OTP 5 times invalidates that code.
   - Correct code returns an access token and sets a refresh cookie; the audit log records `2fa_success` and `login_success`.
3. **Lockout.** *As an owner I want brute force stopped.*
   - 5 consecutive wrong passwords -> HTTP 423 for 15 min and a security-alert email.
4. **Attack blocked.** *As an analyst I want malicious input stopped and visible.*
   - Typing `' OR '1'='1` in the login form shows the 403 screen, and a Critical "SQL Injection" alert appears in the SOC Console with the raw payload.
5. **Triage.** *As an analyst I want to confirm or dismiss alerts.*
   - Opening an alert shows layer, model, confidence, source IP, endpoint and payload; each of the three actions updates status/blocklist and shows a confirmation toast.
6. **Admin-only console.** *As an admin I want only admins to reach the SOC Console.*
   - A valid non-admin login is rejected with "not authorized for the SOC Console" (**target:** enforced server-side as well).

## 8. Success metrics **[PROPOSED]**
- 100% of auth endpoints covered by automated tests; zero crash-causing unhandled rejections.
- Detection: >= 95% precision and recall per class on a held-out labelled set (currently unmeasured).
- All dashboard numbers come from persisted data (0 hardcoded KPI values).
- A new developer/AI can run the whole system from `memory.md` in under 15 minutes.

## 9. Constraints and dependencies
- SMTP account required (Gmail app password suggested). Registration is limited to `@gmail.com` addresses.
- Node.js >= 22.5 (built-in `node:sqlite`), Python 3.x with Flask and scikit-learn.
- Local-only deployment today; no cloud, containers or CI.

## 10. Risks
| Risk | Impact | Mitigation |
|------|--------|-----------|
| Toy model gives false confidence | Misleading demos / evaluation | Real dataset + metrics; label mock numbers in UI |
| Email outage crashes API | Downtime | try/catch + async error wrapper (Phase 1) |
| Admin authz only in browser | Privilege escalation once admin APIs exist | Server-side `requireRole` before adding any admin API |
| Secrets in shared archives | Account/credential compromise | Rotate secrets; `.gitignore` `.venv/`; never share `.env`/`data/` |

## 11. Open questions
See `memory.md` section "Open questions" (project goal/deadline, real network layer, dataset, Gmail-only rule, reset method, deployment target).

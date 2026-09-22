# Rules: How to Work on Aegis

These rules apply to **any AI assistant or human** changing this project. They are derived from patterns already in the code, plus guard-rails for the known weak spots. Keywords: **MUST** / **MUST NOT** / **SHOULD**.

## 0. Session protocol (do this every time)

1. **Read first:** `memory.md` (current state, known issues) -> `phases.md` (current phase) -> `architecture.md` / `prd.md` / `design.md` as needed.
2. **Trust the code over the docs.** If they disagree, say so and propose a doc fix.
3. **Work in small steps**, one concern per change; explain what changed and why.
4. **Before finishing:** update `memory.md` ("Recent changes", "Current focus", any new issues/decisions) and tick items in `phases.md`. If you changed an endpoint, schema, env var or screen, update `architecture.md` / `design.md` in the same change.

## 1. Golden rules

1. **MUST NOT** request, print, log, commit or paste secrets: `.env` values, JWT secrets, SMTP password, tokens, OTPs, TOTP secrets, password hashes, or user data from `data/auth.sqlite`. Refer to env keys by **name** only.
2. **MUST NOT** share or commit `.env`, `data/`, `.venv/`, `node_modules/`.
3. **MUST NOT** present simulated data as real. Mock KPIs, model names and accuracy figures must not be quoted as results (see `memory.md` I-08). When wiring real data, delete the placeholder.
4. **MUST** ask the owner before: changing the auth model (2FA, token lifetimes), changing DB structure in a breaking way, adding a large dependency/framework, or deleting files.
5. **MUST** label guesses as `[ASSUMPTION]` and contradictions as `[MISMATCH]`.
6. **SHOULD** prefer the smallest diff that solves the task; do not reformat unrelated code.

## 2. Backend code rules (Node / Express)

- **Module system:** CommonJS (`require`, `module.exports`). Node >= 22.5.
- **Style:** 2-space indent, double quotes, semicolons, arrow functions, `const` by default, Windows CRLF line endings (don't mass-convert).
- **Structure:** routes for a domain live in one router file; reusable helpers in `utils/`; Express middleware in `middleware/`; one-off tools in `scripts/`.
- **Responses:** errors `res.status(code).json({ error: "Readable message." })`; success `{ message }` or a data object. Use accurate status codes (400 validation, 401 unauthenticated, 403 forbidden, 409 conflict, 423 locked, 429 rate-limited, 503 dependency down).
- **Async handlers:** every `await` on mail, network or crypto **MUST** be inside `try/catch` (Express 4 does not catch async rejections; an unhandled rejection can kill the process). Prefer a shared `asyncHandler` wrapper once it exists.
- **User output:** always serialise with `publicUser(user)`; **MUST NOT** return raw DB rows.
- **Time and IDs:** `Date.now()` (epoch ms) and `uuidv4()`. Lowercase emails before storing/querying.
- **Env access:** `process.env.X`; new required keys are validated at startup; add to `.env.example`.
- **No new global state** for anything that must survive restarts or multiple instances (rate-limit store is already in-memory; don't add more).

## 3. Security rules

For every new or changed endpoint, check all of these:

- [ ] Authentication: `requireAuth` unless intentionally public.
- [ ] **Authorization:** explicit server-side role/ownership check (there is no `requireRole` yet; add it, don't inline role checks in handlers). The browser role check is **not** security.
- [ ] Rate limiter on any unauthenticated or costly route (including `/api/ids/predict`).
- [ ] Input validated (type, length, format); body stays under the 32 kb limit.
- [ ] SQL is parameterised (`?` placeholders). **Never** concatenate user input into SQL.
- [ ] Secrets/tokens stored **hashed** (SHA-256 for random tokens, bcrypt for passwords). Don't add new plaintext token columns.
- [ ] Generic messages where existence of an account could leak; don't reveal internals in errors.
- [ ] `audit(...)` entry for security-relevant success **and** failure.
- [ ] No credentials or PII copied into alerts, logs or console output.
- [ ] Password changes: enforce the same strength policy as registration (8+, upper, lower, digit, special) and revoke sessions.
- [ ] Emails: escape user-supplied values placed in HTML bodies.

Fixed design decisions (do not weaken without approval): 2FA mandatory for all accounts; refresh token in `httpOnly` cookie and rotated; separate JWT secrets for access and pending-2FA; lockout after 5 failures; OTP max 5 attempts.

## 4. Database rules

- Schema lives in `db.js` (`CREATE TABLE IF NOT EXISTS`). There are **no migrations**: any change to an existing table also needs an explicit `ALTER TABLE` path (or documented manual step) and an update to `architecture.md` section 5.
- Use `node:sqlite` synchronous prepared statements. Keep foreign keys ON.
- Timestamps = epoch ms `INTEGER`; booleans = `0/1`; IDs = UUID `TEXT`.
- Purge expired OTP/refresh rows if you add a cleanup job; never delete `audit_log` rows.

## 5. API rules

- Prefix: auth under `/api/auth`, IDS under `/api/ids`; new areas get their own prefix and router (e.g. `/api/alerts`).
- Keep the **ML response contract** `{ malicious, type, confidence, severity, model }` stable; if it changes, update `ml_service/app.py`, `server.js` and the JSX together.
- Document every endpoint (method, path, auth, limiter, request, response, errors) in `architecture.md` section 6.

## 6. ML service rules

- Keep class labels and the severity map centralised in `ml_service/app.py`.
- **MUST NOT** claim accuracy, precision or recall without measuring on held-out data. Any real metric must be produced by code committed to the repo.
- Prefer loading a saved model (`joblib`) over retraining on import once a dataset exists; keep the service bound to `127.0.0.1`.
- Don't send credentials to the model (see I-07): classify only non-secret inputs.
- Document training-data provenance (source, licence, size, class balance) in a README next to the model code.

## 7. Frontend rules

- Follow `design.md` for colours, typography, spacing and components. Reuse `Badge`, `Button`, `Card`; don't introduce a second styling system.
- **Two frontends currently diverge** (`memory.md` I-09): the JSX (IDS + SOC Console, no reset/logout) and the HTML build (real-auth overlay, no IDS). Say which one you are changing. **MUST NOT** add features to the HTML overlay (it hijacks the React app by matching visible button text); port its flows into React components instead. Until consolidation (Phase 5), keep both consistent for any auth-related change or note the drift in `memory.md`.
- Backend base URLs are constants at the top of the file; don't scatter URLs.
- Never store tokens in `localStorage`. Keep the access token in memory; rely on the refresh cookie (`credentials: "include"`).
- Mock data must be visibly identified as mock in code (`seedAlerts`, `ATTACK_PRESETS`) and, when shown to users, in the UI.
- When rendering user-supplied text, use `textContent` / React text nodes (the overlay's `safeName` escaping and text-node comments are the pattern to keep).
- Escape/encode any user-provided text rendered as HTML (the storefront is *deliberately vulnerable*, but only in its demo comment behaviour; never in the real auth pages).

## 8. Testing and verification

There are **no automated tests yet**. Until they exist, verify manually and say exactly what you ran.

| Change area | Minimum check |
|-------------|---------------|
| Auth route | Exercise success + each failure path with curl/Postman; confirm status codes, generic messages, audit rows, and that the server stays up when SMTP fails |
| DB schema | Start with an **empty** `data/` dir and with the existing DB |
| ML | `GET /health` then `POST /predict` for one benign, one SQLi, one XSS sample |
| UI | (both builds) Login -> 2FA, register; (JSX) attack detection (`' OR '1'='1`, `<script>alert(1)</script>`), ML service **off** (regex fallback still works) |

When adding tests (preferred: `node:test` for backend, `pytest` for ML), place them in `tests/` and add an `npm test` script.

## 9. Git and file hygiene

- Commit messages: imperative, scoped (`auth: wrap mailer calls in try/catch`).
- `.gitignore` **MUST** contain `node_modules/`, `.env`, `data/`, `__pycache__/`, and **should** add `.venv/`. Don't commit archives (`files.zip`).
- Don't leave debugging output, hardcoded credentials or absolute Windows paths in committed code (see I-13).

## 10. Communication rules for the AI

- State clearly what you **verified** (ran/read) vs **assumed**.
- If a request conflicts with a rule here, explain the conflict and offer the compliant option.
- Summarise each change: files touched, behaviour change, how to test, docs updated.
- Don't expand scope silently; list suggested follow-ups separately.

## 11. Definition of Done

- [ ] Works locally; failure paths handled; server doesn't crash on dependency errors
- [ ] Security checklist (section 3) passed
- [ ] No secrets/PII in code, logs, or docs
- [ ] `architecture.md` / `design.md` updated if contracts or screens changed
- [ ] `memory.md` updated; `phases.md` items ticked
- [ ] Manual (or automated) verification described in the reply

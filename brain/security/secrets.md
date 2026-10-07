# Secrets Management & Exposure Assessment

## 1. Secrets Inventory & Purpose

| Secret Name | Intended Location | Consumer Component | Criticality | Purpose |
| :--- | :--- | :--- | :--- | :--- |
| `JWT_ACCESS_SECRET` | `.env` (Backend root) | `server.js`, `auth.js` | Critical | Signs operator session JWTs. |
| `PENDING_2FA_SECRET` | `.env` (Backend root) | `server.js`, `auth.js` | Critical | Signs temporary tokens during MFA challenges. |
| `SURICATA_INGEST_TOKEN` | `.env` (Root and VM) | `server.js`, `suricata_forwarder.py`, `aegis_block_sync.py` | High | Pre-shared key authenticating sensor ingest and sync calls. |
| `SMTP_PASS` | `.env` (Production) | `mailer.js` | High | Password for transactional email gateway. |
| `CORS_ORIGINS` | `.env` | `server.js` | Medium | Allowed web origin whitelist. |

---

## 2. Secrets Handling Analysis

### Environment & Configuration Handling
* **Custom `.env` Parser**: `server.js` utilizes a custom regex loader reading `.env`:
  ```javascript
  const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
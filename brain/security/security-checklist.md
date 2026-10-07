```markdown
# Aegis Security Assessment Checklist & Findings

## 1. Assessment Categories

### Authentication & Token Security
* [x] **JWT Separation**: Verified that `JWT_ACCESS_SECRET` and `PENDING_2FA_SECRET` are strictly required and checked for difference at startup.
* [ ] **Missing Control - Password Brute-Force Rate Limiting**: No global or route-specific rate limiting (`express-rate-limit`) on `/api/auth/login`.
* [ ] **Missing Control - Token Revocation**: JWTs are verified statelessly; no token revocation list exists for invalidated operator sessions.

### Authorization & RBAC
* [x] **Role Enforcement Middleware**: Administrative routes enforce `requireRole('admin')`.
* [ ] **Security Weakness - Privilege Escalation Surface**: Ensure role changes in the SQLite database invalidate existing active access tokens immediately.

### Input Validation & Injection
* [x] **Body Size Limits**: JSON parsing limited to 32KB (`express.json({ limit: "32kb" })`).
* [ ] **Missing Control - IP Format Sanitization for Shell Execution**:
  * *Severity*: High
  * *Evidence*: `aegis_block_sync.py` applies IP drop rules.
  * *Risk*: Potential shell injection or iptables rule table corruption if IP strings are not validated using `ipaddress.ip_address()`.
  * *Affected location*: `scripts/aegis_block_sync.py`.
  * *Why it matters*: Root privileges are involved in iptables modifications.
  * *Recommended fix*: Wrap all input IP strings with `ipaddress.ip_address(str(ip))` before building command arguments, and pass arguments as an array to `subprocess.run(shell=False)`.

### CORS & Origin Security
* [ ] **Security Weakness - Permissive Null Origin in Non-Production**:
  * *Severity*: Medium
  * *Evidence*: `server.js` sets `res.setHeader("Access-Control-Allow-Origin", "null")` when `allowNull` is true and credentials are enabled.
  * *Risk*: Exploitable by attackers using sandboxed iframes or `file://` origins to leak authenticated responses.
  * *Affected location*: `server.js` CORS middleware.
  * *Why it matters*: Can lead to Cross-Origin Data Leakage of administrative metrics.
  * *Recommended fix*: Eliminate `origin === "null"` allowance or disallow credentials when origin is `null`.

### Network & Infrastructure Security
* [ ] **Confirmed Vulnerability - Insecure Inter-Service Plaintext HTTP**:
  * *Severity*: High
  * *Evidence*: All sensor ingestion and blocklist synchronization runs over plaintext HTTP (`http://0.0.0.0:4001`).
  * *Risk*: Sensitive telemetry and ingest credentials are vulnerable to packet sniffing and tampering.
  * *Affected location*: `scripts/suricata_forwarder.py`, `scripts/aegis_block_sync.py`, `server.js`.
  * *Why it matters*: Integrity of IDS telemetry and automated firewall defense is completely dependent on untampered communications.
  * *Recommended fix*: Implement TLS encryption for all cross-host traffic.

* [ ] **Security Weakness - Over-Broad Interface Binding**:
  * *Severity*: Medium
  * *Evidence*: `server.js` binds to `0.0.0.0` exposing internal API routes on all interfaces.
  * *Risk*: Directly exposes backend services to external untrusted network interfaces without firewall isolation.
  * *Affected location*: `server.js` (`app.listen(PORT, "0.0.0.0")`).
  * *Why it matters*: Ingest and admin surfaces should only be accessible via trusted host-only adapters or internal subnets.
  * *Recommended fix*: Bind specifically to the dedicated management interface IP or enforce perimeter firewall rules on port `4001`.

### Data Protection & Logging
* [ ] **Security Weakness - Plaintext Credential Exposure in Development Logs**:
  * *Severity*: Low
  * *Evidence*: `mailer.js` writes outbound transactional emails containing verification tokens to `data/outbox.log`.
  * *Risk*: Plaintext credentials readable by local system users.
  * *Affected location*: `data/outbox.log`.
  * *Why it matters*: Violates least privilege and credential confidentiality principles.
  * *Recommended fix*: Exclude one-time tokens from log outputs or restrict permissions on `data/outbox.log` to `0600`.

---

## 2. Findings Summary by Classification

### Confirmed Vulnerabilities
1. **Unencrypted Ingest & Sync Transport**: Inter-host telemetry and automated blocking control traffic transmitted over plaintext HTTP.
   * *Location*: `scripts/suricata_forwarder.py`, `scripts/aegis_block_sync.py`.

### Security Weaknesses
1. **Permissive CORS with Credentials for `null` Origins**: Development mode permits `null` origins with credentials enabled.
   * *Location*: `server.js`.
2. **Missing Firewall Self-DoS Safeguards**: Absence of an immutable IP whitelist in `aegis_block_sync.py` leaves default gateway and localhost susceptible to automated drop rules.
   * *Location*: `scripts/aegis_block_sync.py`.
3. **Outbox Telemetry Logging**: Sensitive authentication tokens persisted to `data/outbox.log`.
   * *Location*: `data/outbox.log`.

### Missing Controls
1. **Rate Limiting**: No rate-limiting middleware on authentication or test endpoints (`/api/auth/login`, `/aegis-test-attack`).
2. **Strict IP Validation**: No explicit use of standard Python `ipaddress` validation prior to passing arguments to system firewall binaries.
3. **Token Revocation System**: Inability to revoke valid JWT access tokens prior to expiration.

### Recommendations
1. Place the backend behind an HTTPS reverse proxy (e.g., Caddy, NGINX) with TLS certificates.
2. Introduce a static subnet exclusion list (e.g. `127.0.0.1`, `192.168.56.1`, default gateway) in `aegis_block_sync.py` to prevent self-lockout.
3. Use `subprocess.run(["iptables", "-A", "INPUT", "-s", validated_ip, "-j", "DROP"], check=True)` avoiding any shell evaluation.
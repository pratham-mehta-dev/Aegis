```markdown
# Attack Surface Analysis

## 1. Network & Public Entry Points

| Protocol / Port | Binding | Component | Authenticated? | Purpose | Surface Exposure |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TCP / 4001** | `0.0.0.0` | Node.js Express Server | Mixed | Web dashboard, REST APIs, Sensor Ingest | Public / Host-Wide |
| **TCP / 5000** | `127.0.0.1` | Python ML Service | No | Machine Learning scoring inference | Localhost only |
| **Promiscuous**| `enp0s3` | Suricata IDS | No | Live Packet Capture & Inspection | Untrusted Network Traffic |

---

## 2. API Endpoint Attack Surface

### Public & Unauthenticated Endpoints
* `GET /health`: Returns `{ ok: true }`. Low risk, but permits service fingerprinting.
* `GET /aegis-test-attack`:
  * *Input*: None (URI path match).
  * *Behavior*: Returns client IP and status message; triggers Suricata alerts on the wire.
  * *Risk*: Potential amplification / alert flooding; allows unauthenticated clients to trigger IDS state changes.
* `POST /api/auth/login`:
  * *Input*: JSON `{ email, password }`.
  * *Risk*: Brute-force attacks, credential stuffing, enumeration if responses differentiate between nonexistent users and bad passwords.
* `POST /api/auth/2fa`:
  * *Input*: JSON challenge verification payload.
  * *Risk*: Token exhaustion, timing attacks if validation is not constant-time.

### Sensor & Ingest Endpoints
* `POST /api/ids/ingest`:
  * *Auth*: Checked against `SURICATA_INGEST_TOKEN`.
  * *Payload*: JSON array of alerts from Suricata `eve.json`.
  * *Risk*: Malformed JSON causing unhandled exceptions; high volume causing memory exhaustion; insertion of spoofed attack data poisoning the ML training/scoring pipelines.
* `GET /api/ids/blocklist`:
  * *Auth*: Checked against `SURICATA_INGEST_TOKEN`.
  * *Risk*: Exposes the list of currently banned IP addresses to authenticated callers.

### Protected Administrative Endpoints
* `GET /api/model/info`:
  * *Auth*: Requires valid JWT and `admin` role (`requireAuth`, `requireRole('admin')`).
  * *Behavior*: Dispatches internal HTTP request to `ML_SERVICE_URL`.
  * *Risk*: Server-Side Request Forgery (SSRF) if `ML_SERVICE_URL` is operator-configurable or dynamically controlled.
* `GET /api/admin/*`, `POST /api/admin/*`:
  * *Auth*: Administrative session tokens.
  * *Risk*: Privilege escalation if role verification middleware fails to validate token revocation or role changes.

---

## 3. System & OS-Level Attack Surfaces

### 1. `iptables` Rule Injection Surface
* **Component**: `scripts/aegis_block_sync.py` running as root.
* **Data Flow**: `Backend DB` -> `JSON API` -> `Python Script` -> `OS Shell / iptables`.
* **Attack Mechanism**: If an attacker can inject invalid characters or shell metacharacters into the banned IP field (e.g. `1.1.1.1; reboot`), and the script executes via subshell or without strict string sanitization, arbitrary command execution at `root` level is possible.
* **Current Safeguard**: Reliance on standard IP formats. Requires strict validation with `ipaddress.IPv4Address`.

### 2. Suricata Parser Attack Surface
* **Component**: Suricata 8.0.3 binary listening on `enp0s3`.
* **Input**: Raw Ethernet frames and IP packets.
* **Risk**: Memory safety vulnerabilities in packet defragmentation, protocol dissection (HTTP, TLS, DNS), and rule matching engines.

---

## 4. Client-Side Attack Surface (Web UI)
* **Static Assets**: Built via Vite/React and served from `frontend/dist`.
* **Catch-all Fallback**: `app.get(/^(?!\/api\/).*/, ...)` serves `index.html`.
* **CORS Exposure**:
  ```javascript
  const allowNull = process.env.NODE_ENV !== "production" && origin === "null";
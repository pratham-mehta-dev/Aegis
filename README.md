# Aegis — AI-driven multi-layer IDPS (prototype)

A working prototype of an intrusion-detection-and-prevention demo:

- **Application Layer** — a Flask + scikit-learn service classifies request payloads
  (Benign / SQL Injection / XSS / Port Scan / DoS Flood / Brute Force).
- **Network Layer** — Suricata captures and detects traffic on a configured Linux
  sensor; the forwarder sends authenticated EVE alert events to
  `/api/ids/suricata/eve`. The isolated lab gateway can enforce admin-approved
  blocks and automatically block a lab client after repeated High-severity
  Suricata alerts. It does not enforce whole-LAN or public-IP blocks. The Attack
  Simulator writes clearly-labelled simulated alerts.
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
| `scripts/suricata_forwarder.py` | Linux service that forwards Suricata EVE alerts to Aegis |
| `scripts/aegis-suricata-forwarder.service` | Example systemd unit for the Linux forwarder |
| `scripts/aegis-lab-gateway.nft` | Isolated lab forwarding/NAT policy; not whole-LAN protection |
| `scripts/99-aegis-lab-gateway.conf` | Persistent IPv4 forwarding setting for the lab gateway |
| `scripts/aegis_block_sync.py` | Syncs admin-approved lab blocks into the gateway nft set |
| `scripts/aegis-block-sync.service` | Least-privilege systemd unit for block synchronization |
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

# 3. Build the frontend (compiled SPA)
npm run build

# 4. Run the single unified server (:4001)
npm run dev                                           # :4001 (serves frontend + API)

# 5. Create an admin (pre-verified; 2FA still mandatory at login)
npm run create-admin -- "Admin" admin@gmail.com 'StrongPass1!'
```

Open **http://localhost:4001** — **Demo Storefront** for the customer flow,
**SOC Console** for the admin login, **Attack Simulator** to generate detections.

### Mail in dev

Without `SMTP_HOST`, emails are printed to the API console and appended to
`data/outbox.log` (verification links and OTP codes are readable there). Configure
SMTP (e.g. a Gmail app password) in `.env` for real delivery.

### Optional Google sign-in

Create a Google OAuth 2.0 web client and set `GOOGLE_CLIENT_ID`,
`GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` in `.env`. For local development,
register `http://localhost:4001/api/auth/google/callback` as an authorized redirect
URI. The button appears only when all three values are set. Google verifies the
Gmail identity, then Aegis still requires the account's existing second factor.
Keep the client secret private and never commit it.

### Suricata event ingestion

Set `SURICATA_INGEST_TOKEN` in `.env` to a unique random secret before connecting a
sensor. Submit EVE alert events to `POST /api/ids/suricata/eve` with
`Authorization: Bearer <SURICATA_INGEST_TOKEN>`. The endpoint stores alert events;
it does not enforce network-wide firewall blocks.

#### Linux sensor forwarder

Make the two files in `scripts/` available on the Ubuntu/Debian sensor, for
example through a repository checkout or a VirtualBox shared folder. From the
repository root on the sensor, create the dedicated service account and install
the forwarder and unit:

```bash
sudo groupadd --system aegis-forwarder
sudo useradd --system --gid aegis-forwarder --no-create-home --shell /usr/sbin/nologin aegis-forwarder
sudo install -D -m 0755 scripts/suricata_forwarder.py /usr/local/libexec/aegis-suricata-forwarder.py
sudo install -D -m 0644 scripts/aegis-suricata-forwarder.service /etc/systemd/system/aegis-suricata-forwarder.service
sudo install -d -m 0750 /etc/aegis
sudo nano /etc/aegis/suricata-forwarder.env
```

Add the host-only Aegis URL and the same token configured in the Windows API's `.env`:

```text
AEGIS_API_URL=http://192.168.56.1:4001
SURICATA_INGEST_TOKEN=<same-private-token-as-Aegis>
```

Protect the token file and start the service:

```bash
sudo chown root:root /etc/aegis/suricata-forwarder.env
sudo chmod 0600 /etc/aegis/suricata-forwarder.env
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-suricata-forwarder
sudo systemctl status --no-pager aegis-suricata-forwarder
```

The service runs as the dedicated `aegis-forwarder` user, forwards only `alert` events, and saves
its read cursor so it can resume after a restart. On its first run it starts at the
end of the existing EVE log; generate a new alert to verify forwarding. Keep the
API reachable only on the trusted lab network and restrict Windows Firewall to
that network. Plain HTTP is for this isolated lab only; use TLS for deployment.

#### Isolated lab block synchronization

The gateway sync agent applies only admin-approved IPv4 blocklist entries in
`10.77.0.0/24`, excluding the gateway address. It requires the gateway ruleset's
`blocked_clients` nftables set and `CAP_NET_ADMIN`; it cannot add rules for other
networks. Three severity-1 (High) Suricata alerts from the same lab client within
five minutes create an automatic block that stays active in Aegis until an admin
removes it. Low and Info alerts, the gateway address, and all addresses outside
the lab subnet are excluded. Entries are refreshed every 10 seconds and expire
from nftables after 2 minutes if the running sync agent cannot reach the API. If
the gateway reboots while the API is unavailable, it starts without dynamic
block entries; the agent reapplies still-active Aegis blocks after reconnecting.

Install the sync agent on the gateway, reusing the `aegis-forwarder` account and
the protected environment file created above:

```bash
sudo install -D -m 0755 scripts/aegis_block_sync.py /usr/local/libexec/aegis-block-sync.py
sudo install -D -m 0644 scripts/aegis-block-sync.service /etc/systemd/system/aegis-block-sync.service
sudo cp -a /etc/nftables.conf /etc/nftables.conf.pre-aegis
sudo install -m 0644 scripts/aegis-lab-gateway.nft /etc/nftables.conf
sudo nft -c -f /etc/nftables.conf
sudo install -m 0644 scripts/99-aegis-lab-gateway.conf /etc/sysctl.d/99-aegis-lab-gateway.conf
sudo systemctl enable --now nftables
sudo sysctl -p /etc/sysctl.d/99-aegis-lab-gateway.conf
sudo systemctl daemon-reload
sudo systemctl enable --now aegis-block-sync
```

Before using the gateway, configure the test client's default route as
`10.77.0.1`. In the SOC Console, manually add `10.77.0.2` to the blocklist and
confirm the client loses public-network access; remove the block and confirm
access returns. Never test this on a home-LAN address or enable whole-LAN rules.

## Security notes

- bcrypt cost 12; OTPs, refresh tokens, email-verify and reset tokens are SHA-256
  hashed at rest; two separate JWT secrets (access vs pending-2FA).
- Mandatory 2FA for every account; lockout 5 fails / 15 min; per-IP rate limits on
  login, OTP, reset, register and `/api/ids/predict`.
- Admin APIs are gated server-side by `requireAuth` + `requireRole("admin")`.
- Passwords are never sent to the IDS or stored in alerts.
- See `docs/rules.md` §3 for the full checklist applied to every endpoint.

# Design

UI/UX reference for Aegis, extracted from `files/idps_frontend_prototype.jsx` (sections 2-5.7), the real-auth overlay in `files/idps_prototype.html` (section 5.8) and the server-rendered pages in `auth.js`. **Two frontends exist and diverge** (see section 9 and `memory.md` I-09). The JSX comments say the look "matches the SOC Console wireframes in the SAD report" **[ASSUMPTION: that report is the original design document; it was not in the zip]**.

## 1. Design principles

1. **Trustworthy and calm.** Navy + white "security console" look; colour is reserved for meaning (severity, status).
2. **Severity first.** Critical/High/Medium/Low colours are consistent everywhere (badges, feed, heatmap, distribution bar).
3. **Two audiences, two moods.** *SOC Console* = dense, dark navy chrome, data tables. *Storefront* = light, simple, consumer-like.
4. **Show the reason.** Every block/alert exposes layer, model, confidence, source, endpoint and raw payload.
5. **Prototype honesty.** Mock data should be identifiable (see section 9).

## 2. Design tokens

### Colour
| Token (JSX const) | Hex | Use |
|-------------------|-----|-----|
| `NAVY` | `#1F3864` | Primary brand, top bars, primary dark buttons, active text |
| `NAVY_DARK` | `#152A4E` | Sidebar, login backgrounds |
| `NAVY_HOVER` | `#22406E` | Active/hover nav item |
| `ACCENT` | `#2E75B6` | Primary action buttons, links, selected filter |
| `BG` | `#F3F5F8` | App/page background |
| `CARD` | `#FFFFFF` | Cards, storefront surface |
| `BORDER` | `#D3D9E0` | 1px borders, dividers |
| `TEXT` | `#2B2F36` | Primary text |
| `MUTED` | `#8A93A2` | Secondary text, labels, icons |
| `RED` | `#E15554` | Critical, blocked, destructive |
| `ORANGE` | `#F2994A` | High, warnings |
| `YELLOW` | `#F2C94C` | Medium |
| `GREEN` | `#27AE60` | Low, allowed, success, "LIVE" |

Severity map (`SEVERITY_COLOR`): Critical = RED, High = ORANGE, Medium = YELLOW, Low = GREEN.
Other literals in use: input background `#FBFCFD`, table header `#EEF2F7`, storefront notice strip `#F1F4F8`, prototype switcher bar `#E7EBF1`, alert-detail payload box `#F7F2F2` (red border), flagged comment `#FDF2F2`, muted-on-dark `#AEBBD1` / `#C7D3E8` / `#6E7C99`, warning text `#8A5A22` on `#FBF3E4`, 403 page background `#1B1F27` with panel `#262B36`, modal scrims `rgba(20,25,35,.55)` and `rgba(11,25,52,.94)`.

### Typography
- Family: `Helvetica, Arial, sans-serif` (server pages: `Arial, sans-serif`, 16px). Monospace for raw payloads.
- Scale in use: page title `text-lg font-extrabold`; card titles `text-sm font-bold`; body `text-sm`; table cells 12px; captions/labels `text-xs` / 11px; KPI value `text-2xl font-extrabold`; 403 code `text-6xl font-extrabold`.

### Shape, spacing, elevation
- Radius: cards `rounded-xl`; buttons/inputs `rounded-md`; badges `rounded-full`; heatmap cells `rounded`.
- Card: white, 1px `BORDER`, no shadow. Toast uses `shadow-lg`.
- Spacing: page padding `p-5`/`p-6`; card padding `p-4`; gaps `gap-2` to `gap-5`; top bar height `h-14`.
- Icons: `lucide-react`, 13-20 px (Shield, AlertTriangle, Search, LogIn, Radar, Ban, FileDown, Settings, Eye/EyeOff, Lock, Send, KeyRound, RefreshCw, LayoutDashboard, ListFilter, Store, Zap, Terminal, Bug, Activity, Wifi...).

## 3. Core components

| Component | Description |
|-----------|-------------|
| `Badge` | Pill, white bold 12px text on a semantic colour (severity, status, "XSS BLOCKED") |
| `Button` | Inline-flex, `font-bold text-sm px-4 py-2 rounded-md`, default fill `ACCENT`, white text, optional leading icon, hover `opacity-90`, active `scale-[0.98]`. Variants by fill: `NAVY` (secondary), `RED` (destructive), semantic colour for attack presets |
| `Card` | White rounded-xl with 1px border |
| `KpiCard` | Card with a 6px coloured left bar, small muted label (UPPERCASE), large value |
| `DetailRow` | Two-column key/value chip on `#FBFCFD` with border |
| Inputs | 1px `BORDER`, `#FBFCFD` fill, `rounded-md`, `px-3 py-2`, `text-sm`, no focus ring beyond `outline-none` (**see accessibility debt**) |
| Toast | Fixed bottom-right, `NAVY` fill, white text, auto-dismiss ~2.2 s |
| Modal | Fixed overlay + centred Card (`max-w-2xl`, scrollable) |

## 4. Layout and navigation

The prototype renders inside a fixed **640 px tall** frame under a grey **prototype switcher bar** (`INTERACTIVE PROTOTYPE - Aegis Security Platform`) with three view buttons: **SOC Console**, **Demo Storefront**, **Attack Simulator**, plus a red "Log Out (name)" when an admin is signed in. This bar is prototype chrome, not part of the product.

## 5. Screens

### 5.1 SOC Console login (`AdminLogin`)
Full-frame `NAVY_DARK` background, centred white card (max-w-sm): navy rounded-square shield icon, title **SOC Console Login**, subtitle "Restricted access - authorized security personnel only", username/email + password (eye toggle), primary button; after step 1 the card switches to a 6-digit code field (email or authenticator). Non-admin accounts get "This account is not authorized for the SOC Console."

### 5.2 SOC Console (admin)
- **Top bar** (`NAVY`, h-14): shield + "SOC Console" left; tab buttons right (icon + label).
- **Sidebar** (md+ only, w-44, `NAVY_DARK`): same four tabs; footer "Signed in as admin@company.com" *(hardcoded placeholder)*.
- **Tabs:** Overview, Alerts, Blocked Sources & Reports, Model Settings.

**Overview**
- Row of 4 `KpiCard`s: *TOTAL ALERTS (24H)* (ACCENT), *CRITICAL* (RED), *BLOCKED SOURCES* (ORANGE), *MODEL ACCURACY* (GREEN, hardcoded 96.4%).
- Left: **Live Alert Feed** card with green dot + "LIVE", "View all ->" link, latest 8 rows: time - layer - attack type - source IP - severity badge.
- Right column (w-80): **Attack-Type Distribution** (segmented horizontal bar + legend with counts; Benign/Normal excluded) and **Severity Heatmap (recent)** (7-column grid of 28 cells coloured by the latest alerts' severity, padded with green).

**Alerts**
- Filter bar: layer pills (All / Network / Application), severity `<select>`, source-IP search input.
- Table columns: Alert ID, Layer, Attack Type, Source IP, Confidence (2 dp), Severity (badge), Status, **View**. Empty state: "No alerts match these filters."
- **Alert detail modal:** title "A-#### - <type> Detected", severity + status badges, meta line (Layer - Engine - Confidence - Time), 2x2 detail rows (Source IP, Target Endpoint, Layer, Model Used), **Raw Payload (captured)** in a red-bordered monospace box, actions: **Confirm & Keep Blocked** (RED), **Mark False Positive** (ACCENT), **Add to Blocklist** (NAVY).

**Blocked Sources & Reports**
- Table: Source IP, Reason, Layer, Blocked Since, Alerts count, **Unblock**; header button **Manually Block IP** (RED, uses `window.prompt`). Empty: "No sources currently blocked."
- **Reports & Export** card: Export CSV / Export PDF (currently only show a toast).

**Model Settings**
- Two cards (Network Layer Model, Application Layer Model) with Algorithm / Accuracy / Trained on / Last trained and a **Retrain Model** button (NAVY, inert). *All values are placeholders.*

### 5.3 Demo Storefront (`DemoStorefront`, user side)
- White page, top nav: store icon + **Aegis** (navy, extrabold) left; **Home**, **Products & Reviews**, "Cart" (inert) right.
- Notice strip: *"Deliberately vulnerable demo storefront - every request below is still passed through the Application Layer Engine before being processed."*
- **Home tab:** centred auth card (max-w-sm):
  - **Customer Login:** email + password (eye toggle), **LOG IN**; links "Create a new account" and "Forgot password?"; hint "Try typing `' OR '1'='1` into a field to trigger detection."
  - **Create your account:** full name, Gmail address, password, confirm password (pattern-validated), **CREATE ACCOUNT**.
  - **2FA step:** "Enter the email/authenticator code", 6-digit numeric input, **VERIFY CODE**.
  - Feedback line under the form (grey rounded box). On success: "Welcome, <name>." (no session UI beyond that).
  - **Forgot password:** modal on a deep navy scrim (`rgba(11,25,52,.94)`) with a card: title "Reset your password", helper text "Enter your account email and we will send a secure reset link." **[MISMATCH: the backend actually emails a 6-digit OTP, not a link]**, email field, **SEND RESET LINK** button, server message in green, "Back to sign in" underlined link. There is no screen after this step.
- **Products & Reviews tab:** product search bar (inert), **Leave a Review** card (input with placeholder hint `<script>alert(1)</script>`, **Post**), **Recent Comments** list (flagged comment = pink card, red border, "[blocked - script tag stripped before render]" and an **XSS BLOCKED** badge).

### 5.4 Access Denied overlay (`AccessDenied`)
Full-frame `#1B1F27`: giant red **403**, "Request Blocked by Aegis", explanation naming the detected attack type, bordered panel with **Reference ID** (alert ID) and time, button "<- Back to site".

### 5.5 Attack Simulator (`AttackSimulator`, demo tool)
- Navy header "Attack Simulator - Demo Mode" with activity icon; intro line.
- Two cards: **Network Layer** presets (Port Scan - nmap, DoS Flood - hping3, Brute Force - hydra) and **Application Layer** presets (SQL Injection, XSS, Benign control). Each preset row has a coloured left bar, icon, name, target and a **Launch** button in the preset colour.
- **Live Detection Result** card: badge "<type> - SENT", verdict line ("<layer> Layer Engine classified request as MALICIOUS/BENIGN (confidence x.xx)"), "blocked/allowed in 0.Xs" (**random**, cosmetic), and "View in SOC Dashboard ->" deep link to the alert.

### 5.6 Server-rendered pages (from `auth.js`)
Plain HTML/CSS, centred card on `#152a4e`, card `#111` with `#39414d` border and 14px radius, Arial, muted text `#b7c4d8`, button `#2e75b6`.
- **Email verified / Verification failed** (title, message, "Return to sign in" link to `FRONTEND_URL`).
- **Reset your Aegis password:** two password fields, **UPDATE PASSWORD**, inline status line (orange error / green success), redirects after ~1.2 s.

### 5.7 Emails (from `mailer.js`)
Plain text plus minimal HTML: "Verify your Aegis account" (30 min link), "Your Aegis login code" (6 digits, 5 min), "Reset your Aegis password" (unused template), "Aegis security alert". Sender name "Aegis Security".

### 5.8 HTML build: real-auth overlay screens (27 Aug build)

The newest `files/idps_prototype.html` keeps the old React login card (renamed banner "Aegis Security Platform"; demo credentials and attack hints hidden; extra links **Create a new account**, **Forgot password?** and the note "Protected with email verification and two-factor authentication.") and adds hand-styled panels. They share one look, **different from the React cards**: full-screen scrim `rgba(11,25,52,.94)`, form card `min(380px, 100% - 32px)`, padding 28, background `#111`, border `#39414d`, radius 14, white text; inputs `#202020` with `#39414d` border, radius 6, padding 12; primary button `#2e75b6` (create-account uses `#284b87`), full width, bold; secondary "cancel" button transparent with `#9aa9c0` text; links `#7da6e8` underlined; status line centred, orange `#f2994a` for errors and green `#55c878` for success.

| Panel / page | Content |
|--------------|---------|
| **Create your account** | "Use your Gmail address and a strong password." Fields: full name, Gmail, password, confirm; client-side pattern checks; success text tells the user to open the verification email first, then sign in |
| **Verify your sign in** | "Enter the 6-digit code from your authenticator app / OTP sent to your email." Single centred numeric input (18px, letter-spacing 4px), **VERIFY CODE**, Cancel |
| **Forgot password (3 steps in one panel)** | 1) "Forgot your password? ... we will send a secure OTP" -> **SEND RESET OTP**; 2) "Verify reset OTP" (6 digits) -> **VERIFY OTP**; 3) "Choose a new password" (new + confirm) -> on success "Password updated. Returning to sign in..." then page reload. Wording correctly says OTP |
| **User home** | White page. Header: brand **Aegis** (navy), nav buttons *Home*, *Products & Reviews*, "Hi, <b>name</b>", red **Log out** (`#e15554`). Content: product search row, "Product Reviews" heading, "Leave a comment" box with **Post Review**, "Recent Comments" list (seeded with alice92 and carol.k). Only the reviews view was observed |
| **Admin home (placeholder)** | Light page `#f3f5f8`, dark navy header "Aegis SOC Console" with "Signed in as <b>name</b>" + **Log out**; heading "Security Operations Center", "Administrator access confirmed for <email>", status box "Authentication complete - Email OTP verified successfully." No alerts, tables or charts |

## 6. Key interaction flows

1. **Register:** form -> client pattern checks -> API -> message "Check your email..." -> click email link -> server page "Email verified" -> back to login.
2. **Login + 2FA:** payload check first -> if benign -> API login -> code screen -> verify -> welcome.
3. **Attack attempt:** payload check flags malicious -> alert created -> **403 overlay** -> "Back to site". Analyst sees the alert under Overview/Alerts.
4. **Triage:** Alerts -> **View** -> modal -> action -> toast -> modal closes.
5. **Simulator -> Console:** Launch preset -> result card -> "View in SOC Dashboard" opens the Alerts tab with that alert selected.

## 7. States and feedback

- Loading: button label changes ("Signing in...", "Verifying...", "Creating...") and the button icon switches to `RefreshCw`.
- Empty: muted centred text in tables and legends.
- Errors: small grey (or amber on the simulator/admin login) message box under the form using the server's `error` text.
- Success: toast (console) or grey message box (storefront); green used for allowed/low/live.

## 8. Responsive behaviour
Tailwind breakpoints: KPI row stacks under `sm`; two-column dashboard stacks under `lg`; sidebar hidden under `md` (top-bar tabs remain); wide tables scroll horizontally (`min-w-[600-700px]`). The 640 px fixed frame is a prototype simplification.

## 9. Design debt and gaps (fix when productionising)

| # | Gap |
|---|-----|
| D-1 | Focus outlines removed (`outline-none`) with no replacement -> keyboard accessibility problem |
| D-2 | Inputs lack `<label for>` association in several places; icon-only buttons lack `aria-label` |
| D-3 | Colour-only severity coding (add text/icon; check contrast of white text on YELLOW `#F2C94C`) |
| D-4 | Mock data is not labelled in the UI (KPIs, accuracy, model cards, "Signed in as", simulator timing) |
| D-5 | JSX build: no logged-in state (token discarded), no logout, no reset screens. Both builds: no TOTP setup / 2FA-method screens and no resend buttons |
| D-6 | `window.prompt` for manual IP block; export buttons are inert |
| D-7 | Fixed 640 px frame and prototype switcher bar are not product UI |
| D-8 | Two frontends diverge: JSX = IDS + SOC Console, HTML = real-auth overlay without IDS (I-09). No design-system file or Storybook. Consolidate in Phase 5 |
| D-11 | Overlay panels use separate hand-written CSS (dark `#111` cards) that does not match the React light cards; the overlay is built by matching visible text and `innerHTML` (I-18) |
| D-9 | Server-rendered pages don't share the React app's tokens |
| D-10 | Email wording mismatch: password-reset OTP is sent with "login code" text |

# 🛡️ SIMShield

**A SIM-Swap Attack Detection & User-Awareness System for Digital-Banking
Subscribers in the Kathmandu Valley, Nepal** — full-stack prototype with 2FA
authentication, machine-learning risk scoring, a bilingual awareness chatbot,
a fraud-team dashboard, privacy-preserving design, and a built-in mixed-methods
user study. 

> ⚠️ **Scope & ethics.** SIMShield is a **defensive detection and awareness**
> tool only. It does **not** perform, simulate, or assist any SIM-swap /
> interception attack. All phone numbers, SIMs, IMEIs, IMSIs, locations and
> operator signals are **synthetic**. Processing is local-only.
>
> **This is an academic prototype, not banking software.** It has not been
> penetration-tested, holds no operator agreement, and its detection model is
> **not validated for deployment**. See
> [`SECURITY_REMEDIATION.md`](SECURITY_REMEDIATION.md) for the threat model,
> the 23 security findings and what remains unfixed.

## Security posture

Run `python -m pytest backend/tests -q` (523 tests) to verify the controls below.

| Control | Status |
|---------|--------|
| Environments (`development` / `demo` / `production`) with a start-up gate that **refuses to boot production** with demo OTPs, demo endpoints, generated keys, wildcard CORS or missing TLS | ✅ |
| `debug=False` always; the Werkzeug debugger cannot be enabled outside development | ✅ |
| CORS **allowlist** from `SIMSHIELD_CORS_ORIGINS` (default: same-origin only) | ✅ |
| CSP `script-src 'self'` with **no nonce and no `unsafe-inline`** (all page logic is in external files), plus XCTO, Referrer-Policy, Permissions-Policy, `frame-ancestors 'none'`, HSTS when TLS is on | ✅ |
| Authentication + roles on operator, study-export, retention and admin routes; per-access audit logging | ✅ |
| OTP never returned outside demo mode; bound to a server-side login challenge and device; every OTP flow rate-limited | ✅ |
| Secrets and generated data git-ignored; `.env.example` provided; **no public salt** | ✅ |
| AES-256-GCM **fails closed** — plaintext PII is never written | ✅ |
| Pseudonyms are keyed HMAC-SHA-256 at 128 bits (was a public-salt 64-bit hash) | ✅ |
| Session in an **HttpOnly cookie** + CSRF double-submit (bearer accepted outside production during a staged migration) | 🟡 |
| Containment simulation is **atomic** — concurrent debits cannot overdraw; held payments cannot be released twice; amounts are whole rupees so the balance arithmetic is exact | ✅ |
| Every API payload schema-validated; 256 KB body limit; structured errors, never a stack trace | ✅ |
| Audit log is **tamper-evident** (not tamper-proof), concurrency-safe, with signed checkpoints that detect truncation | ✅ |
| Retention applied to audit, alerts, study files **and** the database tables | ✅ |
| ML artefacts verified against a SHA-256 manifest before unpickling | ✅ |
| Operator data **fails open** structurally — no configuration can make an outage raise a risk score; measured across 9 degradation modes | ✅ |
| Operator lookups require **explicit consent** (an unstated decision denies) and are audited without any location data | ✅ |
| Operator integration is **simulated**; the CAMARA adapter is a non-operational placeholder with no client, endpoint or credential | 🟡 |
| Analyst decisions require a **reason code** from a fixed taxonomy; the outcome is derived from the code, evidence is required where it counts against the detector, and staff actions are pseudonymised into the audit chain | ✅ |
| Subscribers can **appeal** a restrictive decision; an upheld appeal must be coded as a false positive, and the resulting rate is suppressed below significance | ✅ |
| Drift and fairness monitors **validated against known ground truth** (9/9); cohorts under 30 decisions report no rate at all | ✅ |
| **Passkeys + single-use recovery codes** — factors that survive a SIM swap; every WebAuthn check has its own negative test | ✅ |
| WebAuthn **attestation is not verified** (authenticator model unproven); needs HTTPS + a registered domain outside localhost | 🟡 |

---

## Quick start (Windows / PowerShell)

```powershell
cd simshield
copy .env.example .env             # then edit; development works with defaults
cd backend
python -m venv .venv               # optional
.\.venv\Scripts\Activate.ps1       # optional
pip install -r requirements.txt

python train_model.py    # trains RF + Isolation Forest AND writes models/manifest.json
python seed_demo.py      # creates the SQLite DB + demo accounts (add --reset to wipe)
python evaluate.py       # scenario + study report
python evaluate_ml.py    # honest ML evaluation (PR-AUC, calibration, ablations)
python evaluate_operator.py   # operator-degradation matrix (9 failure modes)
python evaluate_monitoring.py # drift/fairness monitors + self-validation
python -m pytest tests -q   # 523 security and integrity tests
python app.py            # run -> http://127.0.0.1:5000
```

`SIMSHIELD_ENV` selects the environment (`development` by default). In
`development` missing secrets are generated per-process so the app runs with no
setup; they are **not** persisted, so a restart rotates them. `production`
refuses to start unless every secret is supplied and every demo convenience is
off — see `.env.example`.

**Demo credentials** (synthetic):

| Role  | Email                | Password    | Notes |
|-------|----------------------|-------------|-------|
| user  | `aarav@example.np`   | `Demo@1234` | healthy account, safe SIM profile |
| user  | `gita@example.np`    | `Demo@1234` | recent SIM swap → alerts, elevated risk |
| admin | `fraud@simshield.np` | `Admin@1234`| fraud-team dashboard at `/admin` |

> ### 📨 Where is my one-time code? **No email is sent.**
> SIMShield has no mail server configured, so **nothing will ever arrive in your
> inbox**. After the password step the code is shown **on the sign-in page
> itself**, in a banner directly above the code box:
>
> > 📨 **Demo outbox** — no real email is sent in demo mode. Your code is **`######`**
>
> That is a **fresh random 6-digit code every sign-in** (`secrets.randbelow`,
> stored only as a hash, expiring after the configured TTL, and bound to the
> browser session that started the flow). Read the digits off the banner each
> time — there is no fixed code.
>
> The same code is also listed under **fraud desk → Notification outbox**
> (`fraud@simshield.np` / `Admin@1234`).
>
> If that banner is missing, `SIMSHIELD_DEMO_REVEAL_OTP` has been set to `false`
> — with no SMTP configured that makes signing in impossible. Set it back to
> `true` in `.env`, or delete `.env` entirely (development reveals codes by
> default).
>
> **To send real email instead:** set `SIMSHIELD_DEMO_REVEAL_OTP=false` *and*
> configure `SIMSHIELD_SMTP_HOST/PORT/USER/PASS` (a Gmail app password works).
> Do one or the other — turning the banner off without SMTP locks you out.

---

## The pages

| URL | What it is |
|-----|------------|
| `/` | Awareness landing (education, how detection works, playbook) |
| `/login` · `/register` | 2FA sign-in (password → email OTP, pre-OTP risk check) and registration |
| `/dashboard` | **Overview**: one-glance risk verdict (animated ring + trend sparkline) with plain-language reasons, balance/alerts/SIM-events/points tiles, quick actions, alerts and activity feeds, and the SIM-swap demo trigger |
| `/money` | **Exposure**: what a SIM swap on your number would put at risk, and the **cooling-off hold** that contains it — after a SIM change a payment is neither refused nor allowed but *held*, released only by an out-of-band code. Deliberately **not** a banking app: no account number, no merchant, no spending history |
| `/defence` | **Security controls**: emergency freeze/unfreeze (OTP-gated), SIM-event feed, devices, **active-session management**, **self-managed geo-fence safe zones**, notification preferences, **trusted contact**, full activity log |
| `/awareness` | **Education**: what a SIM swap is, warning signs, protection, the bilingual IR playbook, **'Spot the scam' trainer**, gamified checklist and badges, Nepal contact numbers |
| `/assistant` | **Full-page bilingual chatbot** (EN/नेपाली) — explains your own alerts, walks through recovery, escalates to the fraud team |
| `/account` | Redirects to `/dashboard` (the old single-page account view was split into the four pages above) |
| `/admin` | **Fraud-team dashboard**: KPIs, 7-day alert chart, pre-OTP decision distribution, alert queue (resolve/escalate), subscriber list (freeze/unfreeze) with **per-case investigation timelines**, notification outbox, chatbot logs, audit-chain check |
| `/offline.html` | Cached emergency guidance (first-10-minutes steps + Nepal operator/police numbers) shown when the device has no connection — the exact situation a SIM-swap victim is in |
| `/detection` | Detection demo: score synthetic login scenarios, see the fused breakdown |
| `/study` | Mixed-methods user study (consent → pre-quiz → guide → post-quiz + SUS + feedback) |
| `/metrics` | Evaluation dashboard (ML metrics, scenario results, study aggregates) |

### Design system

The UI implements `DESIGN-apple.md`: a single Action-Blue (`#0066cc`) accent,
hairline 18px cards, pill CTAs, 17px body with negative tracking, alternating
light/dark full-bleed tiles. On top of that:

- **One SVG icon family** (`icons.js`, 33 icons, 1.75 stroke, `currentColor`).
  Emoji are never used as structural icons — they render differently per
  platform and can't be themed.
- **Inline animated SVG illustrations** (`illustrations.js`) that *teach* rather
  than decorate: a number hopping to an attacker's SIM, the pre-OTP gate
  holding, signal bars dropping to "No Service", four signals converging into
  one score. Self-contained, so they still render offline in the PWA.
- **Motion discipline**: 150–300ms micro-interactions, 300–450ms staggered
  scroll-reveals, `transform`/`opacity` only, and a global
  `prefers-reduced-motion` override that disables all of it.
- **One shared app shell** (`shell.js`) renders the nav, sub-nav and mobile tab
  bar for every page, so navigation can't drift between files.

> A design-system generator suggested a gold/purple "Exaggerated Minimalism"
> palette for this project. It was **not** adopted: its stated best fit is
> fashion/portfolio work, it recommended a purple accent while listing purple
> gradients as an anti-pattern, and it would have fragmented an already
> documented design language. Its genuinely useful guidance — drop emoji icons,
> the operations-dashboard layout pattern, and the motion timings — was adopted.


---

## Architecture

```
Frontend (vanilla HTML/CSS/JS, Apple-style design system)
   │  fetch/Bearer token
Backend (Flask, modular blueprints)
   ├─ routes/auth_routes.py    registration · password step · pre-OTP risk check ·
   │                           email-OTP 2FA · sessions · password reset
   ├─ routes/user_routes.py    dashboard · alerts · prefs · freeze/unfreeze (OTP) ·
   │                           transactions · checklist · demo SIM-swap injector
   ├─ routes/chat_routes.py    chatbot + history
   ├─ routes/admin_routes.py   fraud-team queue, users, outbox, chat logs (RBAC)
   ├─ engine/detector.py       fuses 4 components -> score + ALLOW/MONITOR/VERIFY/BLOCK
   │     ├─ risk_engine.py       1· SIM integrity + Haversine/sigmoid location
   │     ├─ signals.py           2· behavioural red flags (explainable rules)
   │     ├─ ml_model.py          3· Random Forest (supervised, 100k rows)
   │     └─ anomaly.py           4· Isolation Forest (unsupervised) + Markov
   │                                sequence model (LSTM stand-in, same contract)
   ├─ engine/operator_adapter.py  typed operator boundary (status/freshness/
   │     │                        latency/source/consent) — fails open by design
   │     ├─ operator_mock.py       MockOperatorAdapter: synthetic feed + faults
   │     ├─ operator_camara.py     CAMARA placeholder — NOT_CONFIGURED, no client
   │     └─ operator.py            facade: consent -> adapter -> audit -> engine
   ├─ engine/auth.py           PBKDF2 passwords · OTP · sessions · devices · lockout
   ├─ engine/crypto.py         AES-256-GCM field encryption (phone numbers at rest)
   ├─ engine/notifier.py       email/SMS/push -> outbox (simulated; optional real SMTP)
   ├─ engine/transactions.py   personal-baseline transaction anomaly detection
   ├─ engine/account_risk.py   account-posture risk score for the dashboard
   ├─ engine/chatbot.py        bilingual intent NLU · alert explanation · escalation
   ├─ engine/playbook.py       incident-response playbook (EN/NE)
   ├─ engine/gamification.py   points + badges (config-driven)
   ├─ engine/privacy.py        pseudonymisation · masking · minimisation
   ├─ engine/compliance.py     consent · hash-chained audit log · retention · ethics
   ├─ engine/study.py          mixed-methods study instrument + aggregation
   └─ engine/db.py             SQLite (users, sim_events, transactions, alerts,
                               chat_logs, otp_codes, sessions, devices, outbox,
                               activity_log)  [production: PostgreSQL + Redis]
Config: config.yaml (detection/auth/txn/gamification) · compliance.yaml (privacy/ethics)
```

### Why login risk is scored **before** the OTP
The whole point of SIM-swap fraud is intercepting the SMS OTP. SIMShield's
login flow therefore runs the detection engine **after the password step and
before any OTP is issued**: a BLOCK decision refuses the sign-in and no code
ever exists to steal; VERIFY proceeds because the OTP itself is the step-up.
Accounts registered with a linked telecom profile (`profile_id`) demonstrate
this live — in production that link is the operator's HLR/HSS feed.

### Mobile-operator integration — **simulated, behind a typed adapter**
> **SIMShield has no operator integration.** It holds no agreement with NTC,
> Ncell or Smart Cell, has no credentials, and has never contacted a mobile
> network. Every operator value in this project is synthetic.

What exists is the **boundary** such an integration would sit behind
(`engine/operator_adapter.py`), so the design can be evaluated without the
access:

* `MockOperatorAdapter` — the default and the only adapter that returns data.
  It carries the simulated behaviour the project already had, plus consent,
  freshness, latency, quotas and fault injection.
* `CamaraOperatorAdapter` — a **documented, non-operational placeholder**. Every
  call returns `NOT_CONFIGURED`. The module contains no HTTP client, hostname or
  credential, and a tripwire raises if anyone wires a transport into it. Its
  docstring records what a real GSMA Open Gateway / CAMARA integration would
  require (commercial agreement, CIBA subscriber consent, mTLS, quotas).

Every call returns a typed `OperatorResult` whose `status`, `fresh`,
`latency_ms`, `source` and `consent` are explicit fields — an outage, a stale
reading and a denied consent are different answers, not one absent dict key.

**Failing open is structural.** The mismatch flag is computed only inside the
`usable` branch, so no degraded result can add risk. There is deliberately *no*
`fail_open` config key: a setting can be flipped, a control-flow structure
cannot. `python evaluate_operator.py` measures this across nine conditions —
available, unavailable, timeout, stale, partial, disagreement, rate-limited,
malformed, consent-withdrawn — over all 40 scenarios plus three isolating
probes. Result: **0 fail-closed regressions**; the isolating probe drops
26.3 → 6.8 (VERIFY → ALLOW) under every degraded condition.

Consent is checked at the boundary before any lookup, and a profile that states
no decision resolves to `UNKNOWN`, which **denies** — absence of a record is not
agreement. Every access is audited, including failures, recording status,
freshness, latency and consent but **never** the area, cell ID, coordinate,
phone number or IMSI: auditing a location lookup must not itself become a
location history.

### Scope: SIMShield is not a banking app
The project deliberately does **not** simulate banking. There is no account
number, no merchant field, no spending history and no payments product — those
invite the reader to evaluate SIMShield as payments software, which is not the
contribution and not a claim it makes.

What survives in that area is the one control that is genuinely a SIM-swap
countermeasure: **the cooling-off hold**. For a configurable window after a SIM
change, a payment is neither refused nor allowed — it is **held**, and releasing
it requires a code sent to the subscriber's *email*, a channel whoever holds the
phone number does not control. That is the containment banks already apply once
an operator reports a swap; SIMShield demonstrates it end to end rather than
describing it.

The balance is labelled **"simulated funds at risk"**, and the page says plainly
that SIMShield is not a bank and holds no money. Amounts are whole rupees, which
makes the balance arithmetic exact rather than merely usually-exact — a
production ledger would use integer paisa and decimals, and that simplification
is recorded rather than hidden. `tests/test_scope_boundaries.py` fails if the
banking presentation creeps back, or if the containment control is removed.

### Human-in-the-loop that can actually be reviewed
A fraud analyst closes a case with a **reason code** from a fixed 14-code
taxonomy (`reason_codes.yaml`), and the outcome is *derived* from the code
rather than chosen separately — so a resolution can never claim "false positive"
while citing a confirmed-fraud reason. Codes that count against the detector's
accuracy require an evidence note; an analyst cannot resolve a case about their
own account; and every staff action goes into the same tamper-evident chain as
subscriber decisions, with the analyst pseudonymised.

Cases open automatically on BLOCK and VERIFY, deduplicated per subscriber per
hour so one frustrated retry loop is one investigation.

### Closing the loop on false positives
Subscribers can **appeal** a MONITOR/VERIFY/BLOCK decision from `/defence`. The
appeal opens a case in the same queue, and the analyst's coded resolution becomes
a label the system did not generate itself — the only accuracy figure in this
project whose ground truth does not come from the process being evaluated.

Upholding an appeal means the detector was wrong, so it **must** be recorded with
a false-positive code; the system refuses the contradictory pairing in either
direction. Below 20 reviewed outcomes the rate is reported as **`null`**, not as
a percentage with a caveat — a number that is present gets quoted no matter what
sits beside it.

### Drift & fairness monitoring
PSI over the risk-score distribution and decision mix, plus selection rates by
cohort with the four-fifths disparate-impact ratio.

> The cohort attributes are **FICTIONAL**, marked as such in the fixture data
> itself. No demographic data is collected from anyone. This demonstrates that
> the measurement works — it is not a finding about real subscribers.

`python evaluate_monitoring.py` validates the monitors against drift and
disparity **known by construction** (identical distributions → stable; +15 mean
shift → significant; 3:1 cohort gap → flagged; cohort of 3 → no rate emitted):
**9/9 checks pass**. On this deployment every live figure correctly reports
*insufficient data*, which is the right output at this scale.

### Sign-in that survives a SIM swap
An SMS OTP does not protect against SIM swap — it is precisely what the attack
steals. Two factors here do not travel over the mobile network:

* **Passkeys (WebAuthn)** — full registration and authentication ceremonies,
  hand-written (no library available), with `cryptography` doing the signature
  maths. Each check has its own negative test: forged signature, wrong key,
  replayed challenge, wrong origin, wrong RP ID, wrong ceremony type, absent
  user presence, another account's credential. A regressed signature counter
  raises a clone warning and a critical alert.
* **Recovery codes** — ten single-use PBKDF2-hashed codes, claimed atomically
  (ten racing threads, exactly one winner), in an alphabet without I/O/0/1
  because they get read off paper by someone mid-incident.

> **Limits, stated not implied:** attestation is parsed but **not verified**, so
> the authenticator model is unproven; passkeys need HTTPS and a registered
> domain outside localhost. Both appear in the API response, the UI and the
> config.

### Machine learning
* **Supervised** — RandomForestClassifier on the 100k-row synthetic telecom
  dataset (11 features: IMSI/ICCID/SIM-type change, OTP↔SIM-change gap, SIM
  activation recency, …). ~99% accuracy / 0.999 ROC-AUC on the held-out split
  (optimistic — see model card).
* **Unsupervised** — IsolationForest trained on **legit rows only**; flags
  logins unlike any normal traffic, catching novel patterns.
* **Sequential** — an order-1 Markov chain over each user's own login-event
  stream (time-of-day × device familiarity) scores improbable transitions.
  It is the prototype stand-in for the LSTM/GRU the architecture calls for —
  same interface, swap contained to `engine/anomaly.py`.
* Fusion weights and thresholds live in `config.yaml`; every score ships with
  plain-language reasons and is written to the tamper-evident audit chain.

### Cybersecurity features
2FA (email OTP) · pre-OTP risk gating · PBKDF2 password hashing · account
lockout · **rate limiting on auth endpoints** · AES-256-GCM encryption of PII
at rest · salted-hash pseudonymisation of identifiers · masked display
everywhere · device fingerprinting with new-device alerts · **active-session
listing & revocation** · OTP-gated account freeze/unfreeze · **cooling-off
payment holds after a SIM change (out-of-band release)** · **user-managed
geo-fence safe zones fed into the login risk check (with optional browser
geolocation)** · **trusted-contact out-of-band alerting** · role-based access
control · hash-chained audit log with verify endpoint · data-minimising logs ·
retention windows · out-of-band notification on risky sign-ins.

### Chatbot (user awareness)
Rule-based intent NLU (auditable, no external service; swappable for
Rasa/Dialogflow behind the same `reply()` contract). FAQs, warning signs,
protection steps, OTP safety, **step-by-step recovery guidance from the IR
playbook**, plain-language explanation of the user's own latest alert/ML
score, **escalation to the fraud team**, Nepal-specific contacts — in
**English and नेपाली**, switchable mid-conversation. Every exchange is logged
to `chat_logs`.

---

## Demo scenarios (detection page)

**40 scenarios across 15 synthetic profiles — ten per decision class**, grouped
in the picker on `/detection`. They are both the demo catalogue and the
end-to-end regression suite (`python evaluate.py`).

| Class | n | Score range | Examples |
|-------|---|-------------|----------|
| **ALLOW** | 10 | 6.1 – 10.3 | morning login at home · student on campus · second registered handset |
| **MONITOR** | 10 | 18.6 – 25.9 | traveller in Pokhara · migrant worker in Doha · pensioner locked out at dawn |
| **VERIFY** | 10 | 27.1 – 76.5 | SIM reissued after losing a phone · odd hour on an unknown device · eSIM conversion |
| **BLOCK** | 10 | 85.3 – 97.9 | swapped today, draining fast · attacker at the victim's home zone · serial swapper |

All 40 pass. The suite deliberately includes near-boundary cases (a legitimate
SIM reissue against a genuine swap; a pensioner's failed logins against the same
pattern on an unknown device) so it tests the *edges* between classes, not just
the easy extremes.

### What the suite found

Building it surfaced two real defects that the original five scenarios never
exercised:

1. **A local attacker could escape BLOCK.** With `sim_integrity` weighted 0.55
   and `location` 0.45, a SIM activated *hours* ago scored the maximum 100 on
   integrity, but with distance ≈ 0 the rule component still capped at 55 — so
   "swapped today, draining fast" reached only 77 and fell short of BLOCK.
   SIM recency *is* the defining SIM-swap signal; distance is contextual, and in
   Nepal it also produces false positives for migrant workers. Rebalanced to
   **0.70 / 0.30**.
2. **Using your own second phone raised a device-change flag.** `imei_changed`
   compared only against the most recently used IMEI, so a subscriber with two
   *registered* handsets took a 60-point penalty for picking up the other one.
   It now requires the device to be both different from last time **and**
   unregistered.

Fusion weights were also rebalanced (`behavioral` 0.20 → 0.30, `ml` 0.25 → 0.20)
because the behavioural component saturates at 100 yet contributed only 20
points — a never-seen device plus a burst of failed 01:40 logins landed in
MONITOR when a bank should plainly step up. Thresholds were then set from the
**observed score distribution** rather than by hand; all values and their
rationale are commented in `config.yaml`.

> These are calibrated to synthetic fixtures. Real deployment requires
> re-tuning on real data, with a fresh DPIA and an operator agreement.

> **Fixtures are time-relative by design.** Profiles express ages as
> `sim_activation_days_ago` / `last_login_hours_ago`, resolved at load time by
> `engine/profiles.py`. They previously pinned absolute dates against a frozen
> "demo today" of 2026-07-05, which made them decay silently: five weeks later a
> SIM authored as "1 day old" scored as 39 days old, its SIM-integrity tier fell
> from 100 to 20, and the BLOCK scenario quietly became VERIFY while still
> *looking* correct. Relative ages keep each scenario meaning what its name says
> whenever it is run.

---

## Privacy, ethics & evaluation

* **Privacy-preserving:** identifiers are never stored in the clear
  (salted-hash pseudonyms + AES-256-GCM for the phone number), logs are
  minimised to policy-allowed fields, retention windows purge old data,
  and the study is consent-gated and anonymous. Policy lives in
  `compliance.yaml`, owned separately from detection tuning.
* **Ethical:** machine-readable scope statement (`/api/ethics`), generated
  model card (`models/model_card.md`), human-in-the-loop escalation
  (VERIFY/BLOCK never auto-punish), right-to-explanation on every decision.
* **Mixed-methods evaluation:** system metrics (below) plus user results
  (pre/post knowledge gain, SUS, confidence shift, free-text feedback).
  Study exports are **researcher/admin-only** and audited; qualitative feedback
  is exported separately from the quantitative measures.

### Honest ML evaluation (`python evaluate_ml.py`)

Accuracy is deliberately **not** the headline: on a dataset that is 73.9%
fraud, predicting "fraud" for everything scores 74%. Reported on a **held-out
split never used for threshold tuning** (train 60k / tune 20k / held-out 20k):

| Measure | Value |
|---------|-------|
| PR-AUC (average precision) | 0.9998 |
| Precision (fraud) | 0.9936 · 95% CI [0.9922, 0.9950] |
| Recall (fraud) | 0.9923 · 95% CI [0.9909, 0.9935] |
| **False-positive rate** — the cost to legitimate customers | 1.8% |
| Brier score | 0.0144 |
| Confusion `[[TN, FP], [FN, TP]]` | `[[5125, 94], [114, 14667]]` |

**Ablations** isolate each component: one rule flag alone gives 0.90 precision
at 0.61 recall with a 19% false-positive rate; the Isolation Forest alone
reaches PR-AUC 0.986; the Random Forest 0.9998.

**Adversarial suite** covers a missing operator feed, spoofed browser location,
VPN/IP change, legitimate travel, lost-phone SIM replacement, feature
manipulation and absent location.

**Three weaknesses reported rather than hidden:**
1. **Mid-range probabilities are miscalibrated** — the 0.4–0.5 bin resolves to a
   0.79 observed frequency. Usable for *ranking*, not as a probability.
2. **Extreme feature values do not escalate proportionally** — 9,999 logins
   scores 23.3 because behavioural rules are binary thresholds. The adversarial
   suite prints this as a FLAG on every run.
3. **The scenario suite cannot measure the operator signal.** Its one
   operator-dependent case also fires eight other flags whose raw points (305)
   already exceed the behavioural cap (100), so removing the 65-point mismatch
   flag changes that scenario's score by exactly zero. The degradation matrix
   therefore adds three **isolating probes** where the mismatch is the only
   elevated signal — without them the matrix would pass vacuously.

> **These figures are not evidence of real-world performance.** The base rate is
> unrealistic, all operator signals are simulated, and the model is
> **not validated for deployment**. Real use requires an operator agreement, a
> DPIA and re-tuning on real data.

## Subscriber client: installable PWA (mobile-first)

The **subscriber-facing** surfaces (`/`, `/login`, `/register`, `/account`) ship
as an installable **progressive web app**; the fraud-desk and evaluation pages
stay desktop-oriented by design, because analysts triage cases at a desk.

- **Installable** — `manifest.webmanifest` + generated icons (192/512/maskable +
  Apple touch icon). Installs to the home screen and launches standalone with no
  browser chrome. Manifest shortcuts jump straight to *Freeze my account* and
  *Ask the assistant*.
- **Offline-capable** — `sw.js` caches the app shell. API responses are
  **never** cached (a stale risk score or alert list would be dangerous), but
  navigations fall back to `offline.html`, which carries the first-10-minutes
  recovery steps and the NTC/Ncell/Smart Cell/Cyber Bureau numbers as tap-to-call
  links. A victim mid-attack usually has no service — that is precisely when the
  guidance must still open.
- **Push notifications** — opt-in from Settings, delivered via the service
  worker. This is the out-of-band channel that still reaches a subscriber whose
  **SMS is already compromised**.
- **Mobile-first UI** — bottom tab bar under 834 px, 44 px touch targets, 16 px
  inputs (stops iOS zoom-on-focus), and `safe-area-inset` padding for notch and
  home-bar devices.
- **Connectivity watcher** — a sustained loss of connection prompts the user to
  check whether their *phone* also has no signal, with the operator numbers to
  hand.

> **Scope honesty (documented in `pwa.js`).** The web platform cannot read SIM or
> cellular-radio state. `navigator.onLine` reports whether the browser has a
> network route — a hijacked SIM on a device still connected to Wi-Fi produces
> no signal here at all. The watcher is therefore a **prompt, not a detector**,
> and the UI says so. Authoritative detection stays server-side (operator
> SIM-change feed + the pre-OTP risk engine). Turning that prompt into a real
> detector needs a native client — see below.

## What production would add
PostgreSQL + Redis instead of SQLite · real operator (NTC/Ncell) HLR/HSS
feeds instead of synthetic `sim_events` · an SMS gateway (e.g. Sparrow SMS)
and server-side VAPID/FCM push instead of local service-worker notifications ·
WebAuthn/platform biometrics instead of the demo biometric button · an LSTM/GRU
sequence model served from a dedicated FastAPI/Flask ML microservice · rate
limiting + WAF at the proxy · KMS-held encryption keys.

**Native mobile client (React Native / Flutter).** The one capability the PWA
genuinely cannot provide is reading **cellular connectivity state**. A native
client could watch for loss of mobile service and raise a local warning
unprompted — turning the connectivity *prompt* above into an actual victim-side
*detector*, and complementing the server-side operator feed. That is the single
strongest argument for the native client the architecture describes, and the
clearest piece of future work.

## Credits / basis
* Scoring architecture (Haversine + sigmoid, SIM-integrity weighting,
  ALLOW/VERIFY/BLOCK) adapted from the *Sim-Swap-Sentinel* prototype.
* ML/behavioural approach from *"AI-Driven SIM-Card Fraud Detection System"*
  (IJARCCE 2025).
* Training data: the public synthetic *sim-swap-fraud-detection* 100k dataset.
* Config-driven compliance idea adapted (defensively) from MNSF.
* Visual design system: `DESIGN-apple.md` (Apple web design analysis).

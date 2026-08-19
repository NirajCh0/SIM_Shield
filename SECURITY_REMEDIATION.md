# SIMShield — Security Remediation

**Scope of this document.** SIMShield is an academic, defensive, synthetic-data
prototype for SIM-swap risk detection and user awareness. It is **not**
production banking software and this remediation does not make it so. Nothing
here adds offensive SIM-swap, interception, telecom-exploitation or surveillance
capability; the changes are exclusively defensive hardening, research integrity,
and honest documentation.

**Status legend**

| Mark | Meaning |
|------|---------|
| ✅ | Implemented and covered by an automated test |
| 🟡 | Implemented, partially tested, or deliberately staged |
| 📋 | **Future production work** — documented, not implemented |

---

## 1. Threat model

### Assets
| Asset | Why it matters |
|-------|----------------|
| Subscriber credentials & sessions | Account takeover is the whole attack |
| One-time codes (OTP) | The object a SIM swap exists to steal |
| PII: phone numbers, email, trusted contact | Directly identifying; regulated |
| Pseudonymisation salt / AES key | Compromise re-identifies every audit record |
| Audit log | The accountability claim of the project rests on it |
| Study responses (consented research data) | Ethics approval depends on protecting these |
| ML artefacts (`*.joblib`) | Deserialisation is arbitrary code execution |
| Synthetic balances / transactions | Simulation only, but models a real control |

### Attackers considered
| # | Attacker | Capability assumed |
|---|----------|--------------------|
| A1 | Remote unauthenticated internet user | Can reach any exposed HTTP route |
| A2 | Authenticated subscriber | Valid session; tries to reach other users' data or admin functions |
| A3 | Malicious/curious researcher or marker | Has the source and can run it locally |
| A4 | Network attacker on a shared LAN | Can observe/inject on plaintext HTTP |
| A5 | Web attacker (malicious page in the victim's browser) | Cross-origin requests, XSS if reflected |
| A6 | Supply-chain attacker | Can substitute a `.joblib` or a dependency |
| **Explicitly out of scope** | Mobile operator insider; SS7/telecom attacker; nation-state | Requires operator infrastructure SIMShield never touches |

### Trust boundaries
1. **Browser ↔ Flask app** — untrusted input; every payload validated server-side.
2. **Flask app ↔ SQLite** — same host; DB file is the confidentiality boundary.
3. **Flask app ↔ operator API** — *simulated*. In production this is a
   contractual, authenticated, audited boundary (GSMA CAMARA).
4. **Repository ↔ distribution** — secrets and generated data must never cross it.

### Assumptions
- Runs on a single host, local-only, for demonstration and a small user study.
- All telecom data is synthetic; no real subscriber is represented.
- The operator feed is simulated and is **not** evidence of a working integration.
- There is no HTTPS terminator in the default demo posture.

### Residual risks (accepted, documented)
- SQLite offers no encryption at rest for anything other than the AES-GCM fields.
- The audit log is **tamper-evident, not tamper-proof** — an attacker with write
  access to the file and the ability to run the app can rewrite the whole chain.
  Only an external append-only anchor fixes this (📋).
- Local demo mode intentionally reveals OTPs; that mode must never be exposed.
- No HTTPS by default, so A4 can read traffic in the demo posture.

---

## 2. Findings

Severity uses CVSS-style qualitative bands in the context of *an academic
prototype that may be demonstrated on a network*, not of a deployed bank.

| # | Finding | Severity | Status |
|---|---------|----------|--------|
| F1 | `app.run(debug=True)` — Werkzeug debugger allows RCE if reachable | **Critical** | ✅ |
| F2 | `CORS(app)` with no allowlist — any origin may call the API | **High** | ✅ |
| F3 | No security headers (CSP, XCTO, Referrer-Policy, Permissions-Policy, frame-ancestors, HSTS) | **High** | ✅ |
| F4 | `POST /api/retention/enforce` unauthenticated **and destructive** — any caller can purge the audit log | **Critical** | ✅ |
| F5 | `/api/operator/sim-location` & `/sim-swap-check` unauthenticated — discloses SIM location/swap status for any profile id | **High** | ✅ |
| F6 | `/api/study/aggregate` and `/api/study/export.csv` unauthenticated — research data and free-text disclosed | **High** | ✅ |
| F7 | `demo_reveal_otp` returns OTP values in API responses; no environment gate | **Critical** | ✅ |
| F8 | `data/secret.key`, SQLite DB/WAL, logs and study responses distributable; no `.gitignore` | **High** | ✅ |
| F9 | Public default pseudonymisation salt committed in `compliance.yaml` | **High** | ✅ |
| F10 | `crypto.encrypt()` silently writes `plain:`-prefixed **plaintext PII** when `cryptography` is missing | **High** | ✅ |
| F11 | Pseudonyms are a salted SHA-256 truncated to 16 hex (64 bits) — brute-forceable over a small identifier space | **Medium** | ✅ |
| F12 | Session tokens in `localStorage` — exfiltratable by any XSS | **Medium** | 🟡 staged |
| F13 | No CSRF protection on state-changing routes | **Medium** | 🟡 staged |
| F14 | Balance debit is read-then-write — concurrent transfers can overdraw | **High** | ✅ |
| F15 | Held-transaction release is check-then-act — double release possible | **High** | ✅ |
| F16 | No payload validation — NaN/∞ coordinates, oversized strings, bad types reach the engine and raise 500s | **Medium** | ✅ |
| F17 | No request body size limit | **Medium** | ✅ |
| F18 | Audit append reads last hash then writes without a lock — concurrent writes fork the chain | **Medium** | ✅ |
| F19 | Retention covers only the audit log and study files; DB rows, outbox, chat logs, OTPs, sessions and `alerts.log` grow forever | **Medium** | ✅ |
| F20 | `joblib.load()` on an unverified path — deserialisation is arbitrary code execution | **High** | ✅ |
| F21 | Study accepts unvalidated SUS/quiz values; no rate limit; no duplicate mitigation | **Medium** | ✅ |
| F22 | `/api/score` unauthenticated, writes audit records and triggers alerts — unauthenticated resource consumption | **Medium** | ✅ |
| F23 | Documentation over-claims: "tamper-evident" used loosely, accuracy headlined on imbalanced data, connectivity watcher could be read as SIM detection | **Medium** (academic integrity) | ✅ |

---

## 3. Changes by file

### New
| File | Purpose | Findings |
|------|---------|----------|
| `.gitignore` | Keeps keys, DBs, logs, study data and `.env` out of distribution | F8 |
| `.env.example` | Documented configuration template with no real secrets | F8 |
| `backend/engine/settings.py` | Three environments + production safety gate | F1, F2, F7 |
| `backend/engine/security.py` | CORS allowlist, security headers, body limit, error handling | F2, F3, F16, F17 |
| `backend/engine/validation.py` | Dependency-free schema layer | F16 |
| `backend/engine/artifacts.py` | SHA-256 manifest verification before unpickling | F20 |
| `backend/evaluate_ml.py` | Honest evaluation: PR-AUC, calibration, CIs, ablations, adversarial | F23 |
| `backend/models/manifest.json` | Trusted artefact hashes | F20 |
| `backend/tests/` | 523 automated tests | all |

### Modified
| File | Change | Findings |
|------|--------|----------|
| `backend/app.py` | Removed `CORS(app)` and `debug=True`; authz on operator/study/retention; demo-gating; validated `/api/score`; production gate at import | F1–F6, F16, F22 |
| `backend/routes/common.py` | Cookie sessions, CSRF double-submit, role/ownership checks, per-access audit | F5, F6, F12, F13 |
| `backend/routes/auth_routes.py` | Login challenge binding, rate limits on every OTP flow, validation, generic reset response | F7, F16 |
| `backend/routes/user_routes.py` | Rate limits on unfreeze/release, validated payloads, simulation labelling | F7, F16 |
| `backend/engine/crypto.py` | Fail-closed; `plain:` fallback removed | F10 |
| `backend/engine/privacy.py` | HMAC-SHA-256 keyed pseudonyms at 128 bits | F9, F11 |
| `backend/engine/auth.py` | Challenge-bound OTP, CSRF token issuance | F7, F13 |
| `backend/engine/transactions.py` | Atomic conditional debit; idempotent hold release | F14, F15 |
| `backend/engine/db.py` | Autocommit + explicit transactions, busy timeout, new columns | F14, F15 |
| `backend/engine/compliance.py` | Locked appends, signed checkpoints, full retention, honest wording | F18, F19, F23 |
| `backend/engine/study.py` | Range validation, PIS, rate limit, separated feedback, restricted export | F21 |
| `backend/engine/signals.py` | Registered-device fix; tolerant timestamp parsing (latent 500) | F16 |
| `backend/engine/ml_model.py`, `anomaly.py` | Verified loads only | F20 |
| `backend/compliance.yaml` | Public salt removed; login-area retention policy | F9 |
| `backend/config.yaml` | OTP reveal moved to environment; expanded rate limits | F7 |
| `backend/train_model.py` | Writes the integrity manifest | F20 |
| `frontend/script.js`, `login.html` | Cookie credentials + CSRF header + challenge | F12, F13 |

---

## 4. Tests

```
cd simshield/backend
python -m pytest tests/ --collect-only -q   → 523 tests collected
python -m pytest tests/ -q                  → 523 passed
```

| Suite | Collected | Covers |
|-------|-----------|--------|
| `test_p0_security.py` | 50 | Environment gate, headers/CORS, route authorisation, OTP, secrets/crypto |
| `test_p0_corrections.py` | 39 | **Post-review corrections C1–C3** (entry-point debug, CSP vs served HTML, tokens out of response bodies) |
| `test_p1_integrity.py` | 40 | Concurrency, payload validation, audit/retention, artefact integrity |
| `test_p2_research.py` | 24 | Study integrity and honest-claims assertions |
| `test_operator_adapter.py` | 82 | **Improvement #1** — fail-open across 9 degradation modes, typed results, consent, privacy, CAMARA placeholder inertness |
| `test_case_management.py` | 34 | **Improvement #2** — reason-code taxonomy, derived outcomes, evidence enforcement, separation of duties, staff audit |
| `test_appeals_feedback.py` | 31 | **Improvement #3** — appeal/decision consistency, measured false-positive rate, retention |
| `test_monitoring.py` | 25 | **Improvement #4** — PSI drift, disparate impact, sample-size gating, monitor self-validation |
| `test_passkeys.py` | 84 | **Improvement #5** — WebAuthn ceremonies with a negative test per check, CBOR decoder, recovery codes |
| `test_frontend_contract.py` | 78 | Served markup vs backend vocabulary: CSS classes, script resolution, **API response shapes**, service-worker staleness |
| `test_scope_boundaries.py` | 36 | SIMShield is not a banking app: presentation, data minimisation, containment control, whole-rupee arithmetic |
| **Total** | **523** | |

> **Count reconciliation.** Counts in this document have been wrong before. An
> early draft said 109 while the summary said 110, because the document was not
> updated when a test was added. That was superseded by **149** after the
> post-review corrections, and the figure now stands at **523 collected / 523
> passed** after improvements #1–#5, the frontend-contract suite and the scope
> correction.
>
> Every count here is taken from `pytest --collect-only -q`, not from memory. A
> pre-thesis audit re-derived all of them from a live run and found this table
> still listing only 5 of the 11 suites, with `test_operator_adapter.py` off by
> one — corrected above. **Re-run the audit before submitting**; documentation
> drifts faster than code.

Notable behavioural tests (not just assertions on config):
- **Ten threads racing to spend the same balance** — exactly one succeeds, balance never negative.
- **Six threads racing to release one held transaction** — exactly one debit occurs.
- **Twenty threads appending to the audit log** — the chain still verifies.
- **Forging a past audit entry** — detected.
- **Truncating the audit log after a checkpoint** — detected.
- **Tampering with a `.joblib`** — refused, engine degrades to rules-only.
- **OTP replay from a different device/challenge** — rejected.

Two tests initially failed for the *right* reason: linking a test account to the
compromised `sita_swapped` profile caused the pre-OTP check to BLOCK the login.
The fixtures were changed to a safe profile; the control was not weakened.

### Post-review corrections (found by source review, not by the first test pass)

Three P0 defects survived the first remediation because the tests asserted on
**configuration** rather than on **application behaviour**. This is the most
important lesson in this document.

| ID | Defect | Why the original test missed it | Fix | New test |
|----|--------|--------------------------------|-----|----------|
| C1 | `app.py` still ended with `app.run(debug=True, port=5000)` | The test checked `settings.debug_enabled()` in isolation and never touched the entry point | Entry extracted into `run_config()` / `main()`; debug is `settings.debug_enabled()` | `test_main_invokes_run_with_debug_false` monkeypatches `app.run` and asserts the real kwargs; `test_source_contains_no_hardcoded_debug_true` |
| C2 | CSP sent `script-src 'self' 'nonce-…'` but **no `<script>` tag carried a nonce** — a real browser would have blocked every script on all 13 pages, breaking the entire UI while the header looked strict | The test asserted the header string and never inspected served HTML | All 13 inline blocks extracted to external `*.page.js`; the inline `onclick` in `offline.html` removed; policy is now plain `script-src 'self'` and the unused nonce generator deleted | `test_served_page_has_no_inline_script` and `…_event_handler` (13 pages each), `test_every_script_the_login_page_loads_is_same_origin_and_200`, `test_login_page_logic_is_present_in_its_external_file` |
| C3 | Login and OTP responses returned `token` and `csrf_token` in the JSON body, handing JavaScript exactly what `HttpOnly` exists to withhold | No test asserted on the *absence* of a field | Both removed; session travels only in the HttpOnly cookie, CSRF only in its own readable cookie; `login.page.js` and the test fixture read from the cookie jar | `test_login_response_leaks_no_tokens`, `test_verify_otp_response_leaks_no_tokens`, `test_session_cookie_is_httponly_and_samesite`, `test_authenticated_request_works_from_cookies_alone` |

**C2 was the most serious**: the application would have been non-functional in
any real browser, and the automated suite would still have reported success. The
generalised fix is that security tests must assert on what is *served*, not on
what is *configured*.

### Bugs found by the new tests
1. **`signals._parse_ts` crashed on a missing timestamp**, producing a 500 from
   `/api/score`. Timestamp is an optional field; parsing is now tolerant and
   dependent signals simply do not fire.
2. **Self-deadlock introduced during the atomicity work** — activity logging
   inside a write transaction opened a second connection and waited on the lock
   the same thread held. Logging moved outside the transaction.

---

## 5. Implemented vs. future production work

### Implemented in this prototype
- Environment separation with a production safety gate
- CORS allowlist and a full security-header set
- Authentication/authorisation on every sensitive route
- OTP confined to demo mode, bound to a server-side login challenge
- Secrets removed from distribution; fail-closed cryptography; HMAC pseudonyms
- Atomic financial simulation with concurrency tests
- Schema validation and structured errors
- Concurrency-safe, checkpointed audit log with full retention coverage
- ML artefact integrity verification
- Study integrity controls and honest ML evaluation

### 📋 Future production work (explicitly NOT implemented)
| Item | Why it needs real infrastructure |
|------|----------------------------------|
| Real operator feed (SIM-swap / location) | Requires a commercial agreement, OAuth2 credentials and consent with NTC/Ncell |
| HTTPS/TLS termination and HSTS preload | Requires a real domain and certificate |
| External append-only audit anchor (e.g. transparency log) | Local files cannot be made tamper-*proof* |
| KMS/HSM-held keys and rotation | The prototype uses an environment-supplied key |
| WebAuthn/passkeys | Needs a registered relying-party domain |
| Real SMS/push delivery | Needs an SMS gateway and FCM/APNs credentials |
| Production rate limiting / WAF | Belongs at the reverse proxy, not in-process |
| Penetration test and DPIA | Organisational processes, not code |

---

## 6. Staged migration: session transport (F12/F13)

**Done now.** Sessions are issued as `HttpOnly; SameSite=Lax` cookies (`Secure`
when TLS is configured) with a CSRF double-submit token. A strict CSP with a
per-response nonce and **no `unsafe-inline` for scripts** is enforced today.

**Still staged.** The `Authorization: Bearer` header is still *accepted* outside
production so the existing pages and the test suite keep working. In production
`session_token()` ignores the header entirely, so a real deployment is
cookie-only. Remaining steps, in order:

1. Remove inline `<script>` blocks from the pages (they are why `style-src`
   still needs `'unsafe-inline'`; scripts are already nonce-based).
2. Delete the bearer branch in `routes/common.session_token()`.
3. Rotate the session token on privilege change and add idle timeout.

---

## 7. Remaining limitations (honest)

| Limitation | Impact | Why not fixed here |
|------------|--------|--------------------|
| `style-src 'unsafe-inline'` | A CSS-injection vector remains | Pages use inline `style=` attributes throughout; removing them is a large refactor |
| Bearer header accepted outside production | XSS could still steal a session in dev/demo | Staged migration; production is cookie-only |
| In-process rate limiter and login challenges | Reset on restart; not shared across workers | Prototype runs single-process; Redis is the production answer |
| Audit is tamper-**evident**, not tamper-proof | An attacker with write access + this code can rewrite the chain | Needs an external append-only anchor |
| SQLite, no encryption at rest beyond AES-GCM fields | Disk access reveals non-PII columns | Prototype scope |
| No HTTPS by default | Demo traffic is observable on a LAN | Needs a real certificate |
| Mid-range probability miscalibration | Predicted 0.45 → observed 0.79 | Documented; would need isotonic/Platt calibration on realistic data |
| Extreme feature values do not escalate proportionally | 9,999 logins scores the same as 6 | Behavioural rules are binary thresholds — documented, see §8 |
| **Operator integration is simulated end to end** | No figure in this project says anything about a real telecom feed | Requires a commercial agreement, CIBA consent and an ethics review; the boundary is defined instead (§10) |
| The 40-scenario suite cannot measure the operator signal | Its one operator case is saturated above the behavioural cap, so removing the signal changes nothing | Fixed *within* the matrix by adding isolating probes rather than by re-authoring the scenario suite |
| Operator rate limiting and quotas are in-process | Reset on restart; not shared across workers | Same constraint as the auth rate limiter — Redis is the production answer |
| `ASSUMED_COLOCATED` is reported to the user | A subscriber may read "your SIM is here" as a network fact | Typed distinctly and labelled in the UI copy; it is never scored |

---

## 8. Claims that must be corrected in the thesis

| Claim to remove or change | Replace with |
|---------------------------|--------------|
| "Tamper-proof audit log" | "Tamper-**evident** local audit log with signed checkpoints; tamper-proofing requires an external append-only anchor" |
| Headline "~99% accuracy" | "PR-AUC 0.9998 on a **synthetic dataset with a 73.9% fraud rate**; accuracy is uninformative at that balance. Precision 0.993, recall 0.992, FPR 1.8% on a held-out split never used for tuning" |
| Any implication that metrics predict real performance | "All data and operator signals are synthetic; the model is **not validated for deployment** and thresholds must be re-tuned on real data" |
| "Detects SIM swaps" (unqualified) | "Detects **risk indicators** of SIM-swap fraud; authoritative SIM state comes only from the operator" |
| Connectivity watcher framed as SIM detection | "A **prompt**, not a detector — the web platform cannot read SIM or cellular state" |
| "Secure banking application" | "Defensive academic prototype; not production banking software" |
| Operator integration described as working | "**Simulated** operator feed modelled on the GSMA CAMARA contract; no operator agreement exists" |
| "SIMShield integrates with NTC/Ncell via CAMARA" | "SIMShield defines a **typed adapter boundary** for CAMARA-shaped operator APIs and implements a **local mock** against it. The CAMARA adapter is a documented, non-operational placeholder: it has no client, no endpoint and no credentials, and always returns `NOT_CONFIGURED`. No operator has been contacted." |
| "The system degrades gracefully if the operator is unavailable" (asserted) | "Degradation is **measured**: across nine operator conditions over 40 scenarios and 3 isolating probes, **0 of 360 decisions became more restrictive**. The isolating probe moves 26.3 (VERIFY) → 6.8 (ALLOW) when operator data is lost, and never upward. Failing open is structural — the mismatch flag is computed only on the usable branch and no configuration key can disable it." |
| "Operator lookups are consented" (asserted) | "Consent is resolved at the adapter boundary before any lookup; a record that states no decision resolves to `UNKNOWN`, which **denies**. Every access is audited — including denials and failures — recording status, freshness, latency and consent state, and **never** the area, cell ID, coordinate, phone number or IMSI." |
| "Human-in-the-loop review" (unqualified) | "Analyst decisions are recorded with a **reason code from a fixed 14-code taxonomy**; the outcome is derived from the code, evidence is required for codes that count against the detector, an analyst cannot resolve a case about their own account, and every staff action is written to the tamper-evident chain with the analyst pseudonymised" |
| "The system achieves a 1.8% false-positive rate" | "1.8% is measured against **synthetic dataset labels** — the model marked by the process that generated its training data. A second, human-labelled rate is derived from analyst-coded case outcomes; it is reported with its denominator, suppressed below 20 reviewed outcomes, and is a **lower bound** because appeals are self-selected. The two are not comparable." |
| "Fairness analysis shows no disparity" | "Fairness monitoring is **implemented and validated against disparities known by construction (9/9 checks)**. On this deployment every cohort is below the 30-decision minimum, so **no disparity ratio is reported at all**. The cohort attributes are fictional; the analysis demonstrates that the measurement works, not a finding about real subscribers." |
| "SIMShield uses passkeys" | "WebAuthn registration and authentication are implemented and tested against forged signatures, replayed challenges, wrong origins and wrong RP IDs. **Attestation is not verified**, so the authenticator model is not proven, and a real deployment requires HTTPS and a registered domain." |
| "Two-factor authentication protects against SIM swap" | "An SMS OTP does **not** protect against SIM swap — it is the thing the attack steals. Passkeys and single-use recovery codes are the factors that survive it, and the system tells the subscriber when every factor they hold still depends on their phone number." |
| "SIMShield includes a banking module" / any framing of it as a banking app | "SIMShield is **not** a bank and simulates no banking product. It models one bank-side **containment** control — the cooling-off hold applied after a SIM change, released out-of-band — because that is a SIM-swap countermeasure. No account number, merchant or spending history is collected." |

## 9. Proposed next improvements — NOT IMPLEMENTED, awaiting approval

Ranked by academic value per unit of effort. None of these has been built.

| # | Improvement | Effort | Academic value | Privacy impact | Synthetic-data feasible? |
|---|-------------|--------|----------------|----------------|--------------------------|
| ~~1~~ | ~~**Operator API adapter interface + local mock**~~ — **APPROVED AND IMPLEMENTED, see §10** | S (1–2 days) | **High** — makes the central architectural claim concrete and testable | Neutral (improves auditability) | ✅ Fully |
| ~~2~~ | ~~**Fraud-analyst case management with reason codes**~~ — **IMPLEMENTED, §11** | M (3–5 days) | **High** — human-in-the-loop is claimed but thin; reason codes make decisions reviewable | Low (staff actions already audited) | ✅ Fully |
| ~~3~~ | ~~**User appeal / false-positive feedback loop**~~ — **IMPLEMENTED, §12** | M (3–4 days) | **High** — closes the loop on the FPR the evaluation now reports, and is a genuine fairness contribution | Low–medium (appeals are personal data; needs retention) | ✅ Fully |
| ~~4~~ | ~~**Model drift & fairness monitoring dashboard**~~ — **IMPLEMENTED, §13** | M–L (5–7 days) | Medium–high — the model card admits no fairness analysis was possible | Medium (needs cohort attributes — use synthetic ones only) | 🟡 Partly — needs synthetic demographics, which must be clearly labelled |
| ~~5~~ | ~~**WebAuthn / passkeys + recovery codes**~~ — **IMPLEMENTED, §14** | L (7–10 days) | Medium — strong story (removes the OTP entirely) but needs a registered domain | Positive (no shared secret) | 🟡 Partly — works on localhost; real deployment needs HTTPS + RP ID |

**Deliberately ranked lowest / not recommended now**

- *Privacy-preserving aggregate telemetry* (differential privacy over usage
  counts). Elegant, but with a study of ~20 participants the noise required for
  a meaningful ε destroys the signal. Better as future work than as a chapter.
- *Controlled phishing-awareness experiment.* Academically valuable, but it
  involves **deception of human participants** and would require a new ethics
  application, a debrief protocol and supervisor sign-off. Do not start it
  inside the existing approval. If pursued: no real credentials collected,
  immediate debrief, opt-out honoured, and no data linked to individuals.

### Why #1 is first
The thesis argues SIMShield is the bank-side half of a bank+operator system.
Today `engine/operator.py` is a single simulated module. Extracting a formal
`OperatorAdapter` interface with a `MockOperatorAdapter` implementation would:
let the engine be tested against operator *unavailability*, *latency* and
*disagreement*; make the integration contract explicit enough for a real
operator conversation; and cost little because the seam already exists.

---

## 10. Improvement #1 — Operator Adapter interface + local mock (IMPLEMENTED)

Approved and built. **Scope discipline: this added no offensive, interception,
telecom-access or surveillance capability.** It defines a boundary and a
synthetic mock; nothing in it can contact a network.

### What was built

| File | Role |
|------|------|
| `backend/engine/operator_adapter.py` | **New.** `OperatorStatus` (11 members), `ConsentState`, frozen `OperatorResult`, payload types, `OperatorAdapter` base, `safe_call`, adapter registry |
| `backend/engine/operator_mock.py` | **New.** `MockOperatorAdapter` — synthetic feed, area-named fixtures, sliding-window quota, 9 injectable faults |
| `backend/engine/operator_camara.py` | **New.** Non-operational placeholder; `NOT_CONFIGURED` always; tripwire raises on any transport attempt |
| `backend/engine/operator.py` | **Rewritten** as the facade: consent → adapter → audit → engine. Holds the single fail-open branch |
| `backend/engine/compliance.py` | `record_operator_access()` (allowlisted audit fields), `operator_consent_state()`, `_append()` extracted |
| `backend/engine/signals.py` | Comment corrected to state the guarantee; surfaces `operator.explain()` for the UI |
| `backend/evaluate_operator.py` | **New.** The 9-condition degradation matrix + 3 isolating probes |
| `backend/tests/test_operator_adapter.py` | **New.** 82 tests |
| `backend/config.yaml` | `operator:` block — adapter, timeout, freshness, quota, threshold. **No `fail_open` key, by design** |
| `backend/compliance.yaml` | `require_for_operator_lookup: true` |
| `backend/data/users/*.json` (15) | Explicit `operator_consent` field added — no data removed |
| `backend/scenarios.py`, `backend/evaluate_ml.py` | Operator fixtures migrated from coordinates to place names |
| `backend/app.py` | Operator routes return typed status; new `/api/operator/health` |

### The five typed fields
`status`, `fresh`/`age_seconds`, `latency_ms`, `source`, `consent` are required
constructor arguments on `OperatorResult`. There is no default that could hide a
problem, and `usable` is true only when the status is `AVAILABLE` **and** the
data is fresh **and** consent permits **and** a payload is present.

### Fail-open: structural, not configured
The mismatch flag is computed inside the `if result.usable` branch of
`engine/operator.py`. Every other path returns a dict whose risk-bearing fields
are falsy. `safe_call` additionally converts an adapter exception into
`UNAVAILABLE`, a non-`OperatorResult` return into `MALFORMED`, and an
over-budget latency into `TIMEOUT` — so even an adapter written by someone who
ignored the contract cannot make the engine fail closed.

**Measured** (`python evaluate_operator.py`):

| Condition | ALLOW | MONITOR | VERIFY | BLOCK | usable | flagged | fail-closed | probe Δrisk |
|---|---|---|---|---|---|---|---|---|
| available | 10 | 10 | 10 | 10 | 2 | 1 | 0 | — (26.3, VERIFY) |
| unavailable | 10 | 10 | 10 | 10 | 0 | 0 | 0 | −19.5 → ALLOW |
| timeout | 10 | 10 | 10 | 10 | 0 | 0 | 0 | −19.5 → ALLOW |
| stale | 10 | 10 | 10 | 10 | 0 | 0 | 0 | −19.5 → ALLOW |
| partial | 10 | 10 | 10 | 10 | 0 | 0 | 0 | −19.5 → ALLOW |
| disagreement | 10 | 10 | 10 | 10 | 0 | 0 | 0 | −19.5 → ALLOW |
| rate_limited | 10 | 10 | 10 | 10 | 0 | 0 | 0 | −19.5 → ALLOW |
| malformed | 10 | 10 | 10 | 10 | 0 | 0 | 0 | −19.5 → ALLOW |
| consent_withdrawn | 10 | 10 | 10 | 10 | 0 | 0 | 0 | −19.5 → ALLOW |

**0 of 360 scenario decisions became more restrictive.**

### A finding this work produced: the matrix would have passed vacuously
The 40-scenario distribution is **identical in all nine rows**, which initially
looked like a clean pass. It is not evidence of anything. The suite's only
operator-dependent scenario ("Spoofed location, SIM says otherwise") also fires
eight other flags whose raw points sum to **370 with the signal and 305 without
it — both above the behavioural cap of 100**. Removing a 65-point flag therefore
changes that scenario's score by exactly zero.

Had the matrix shipped on the scenario suite alone, it would have "proved"
fail-open while being incapable of detecting a fail-closed regression. The three
**isolating probes** — an ordinary login whose only elevated signal is the SIM
mismatch — supply the real measurement: 26.3 → 6.8 when the signal is lost, and
a flat 6.8 for the control probe whose SIM is where it should be.

This is the same failure mode as post-review correction C2: *a green result that
measures the wrong thing*. It is recorded here because it is a methodological
finding, not a bug.

### Privacy
Operator-derived location never exists as a coordinate. Fixtures name a place;
the adapter resolves it against the public gazetteer in `engine/geo.py` and
returns `area` + scalar `distance_km` + band. `SimLocationData` has no `lat`/
`lon` field, and a test asserts the type cannot grow one. Audit records use an
explicit allowlist — a test writes a real lookup and asserts the reported area,
the cell ID and the coordinate digits are absent from the file on disk.

### CAMARA placeholder — inert by test, not by promise
`test_it_contains_no_http_client_or_endpoint` greps the module for `requests`,
`httpx`, `urllib.request`, `http://`, `https://` and `socket.`.
`test_no_credentials_are_configured_anywhere` asserts all five
`SIMSHIELD_CAMARA_*` variables are unset. `_perform_request` raises
`CamaraNotImplemented`. Selecting the adapter degrades every decision safely.

---

## 11. Improvement #2 — Case management with reason codes (IMPLEMENTED)

**The gap.** SIMShield claimed human-in-the-loop review, but an analyst could
mark an alert `resolved` and nothing recorded *why*. A decision nobody can
review is not a control — it cannot be counted, compared between analysts, or
disagreed with later.

**The fix.** A case carries a **reason code from a fixed taxonomy**
(`reason_codes.yaml`, 14 codes across 5 outcomes), and the outcome is *derived*
from the code inside the engine rather than accepted from the client. Four
constraints are enforced in `cases.resolve()`:

| Constraint | Why it exists |
|---|---|
| `resolved` is unreachable via the status route | Otherwise a case closes with no justification — the original gap |
| Outcome derived from the code, never supplied | A resolution cannot claim "false positive" while citing a fraud code |
| Codes marked `requires_evidence` demand an evidence note | The codes that count against the detector must be justified |
| An analyst cannot resolve a case about their own account | Separation of duties |

Cases open automatically on BLOCK (critical) and VERIFY (medium), deduplicated
per user per hour — a subscriber retrying a blocked login five times is one
investigation, not five. Every analyst action is appended to the tamper-evident
chain via `compliance.record_staff_action()`, with the analyst **pseudonymised**
on the same terms as a subscriber.

**Files:** `reason_codes.yaml`, `engine/cases.py`, `engine/compliance.py`
(`record_staff_action`), `routes/admin_routes.py` (10 endpoints), `engine/db.py`
(`cases`, `case_notes`), `frontend/admin.{html,page.js}`.
**Tests:** `tests/test_case_management.py` — 34.

---

## 12. Improvement #3 — Appeal / false-positive feedback loop (IMPLEMENTED)

**The gap.** The evaluation reports FPR = 1.8%, measured against labels the
synthetic dataset shipped with — the model marked by the same process that wrote
its exam. Nobody who was wrongly stopped could say so.

**The fix.** A subscriber can appeal a MONITOR/VERIFY/BLOCK decision. The appeal
opens a case in the same reviewed queue, and the analyst's coded resolution
becomes a **label the system did not generate itself**. `engine/feedback.py`
measures the false-positive rate against those labels.

The consistency rule is the core of it: **upholding an appeal means the detector
was wrong**, so it must be recorded with a code that counts as a false positive.
`appeals.review()` refuses both mismatches — an analyst cannot record a
sympathetic "upheld" while citing a code that leaves the accuracy figures
untouched, nor reject an appeal while citing an FP code. If the case resolution
then fails (e.g. missing evidence), the appeal decision is rolled back rather
than left inconsistent with its case.

**Honesty controls on the resulting number:**
- Below 20 reviewed outcomes the rate is **`null`**, not merely flagged. A
  number that is present gets quoted regardless of the caveat beside it; the
  only reliable way to keep "100% false positives (n=3)" off a slide is to not
  emit it. Raw counts remain, because those are honest at any size.
- `inconclusive` and `duplicate` outcomes are excluded from the denominator
  entirely — counting "we could not tell" as a correct decision would flatter
  the detector.
- Wilson intervals, not the normal approximation, which at these sample sizes
  produces bounds below 0 or above 1.
- The report states in-band that it is **not comparable** with the model-card
  figure, and that appeals are self-selected so it is a **lower bound**.

**Files:** `engine/appeals.py`, `engine/feedback.py`, `routes/user_routes.py`,
`routes/admin_routes.py`, `engine/db.py` (`appeals`), `compliance.yaml`
(`appeal_days`), `frontend/defence.{html,page.js}`, `frontend/admin.{html,page.js}`.
**Tests:** `tests/test_appeals_feedback.py` — 29.

---

## 13. Improvement #4 — Drift & fairness monitoring (IMPLEMENTED)

**Drift.** PSI over the risk-score distribution (reference window vs recent) and
over the decision mix. Empty buckets are floored at 1e-4, without which a bucket
nobody lands in reports *infinite* drift.

**Fairness.** Selection rate (VERIFY+BLOCK) by cohort across four dimensions —
operator, age band, region, settlement — with the four-fifths disparate-impact
ratio and a breakdown of upheld appeals by cohort.

**The cohort attributes are FICTIONAL** and marked as such in the fixture data
itself (`synthetic_cohort._note` in all 15 profiles), not only in the code. No
demographic data is collected from any real person. What this measures is
whether the pipeline produces disparate outcomes across groups *as constructed*
— a demonstration that the measurement exists and works, not a finding about
Nepali subscribers. A test asserts every profile carries that marking.

**Sample size is enforced, not suggested.** Cohorts under 30 decisions get
`selection_rate: null`; PSI needs 50 per window. Small cohorts are *excluded*
from the disparate-impact ratio rather than counted as zero — otherwise a tiny
unrestricted group manufactures a reassuring ratio out of nothing — and the
`comparable_cohorts` count drops so the exclusion is visible.

**The monitors are validated against known ground truth.** A monitor that never
fires is indistinguishable from one that is broken, so `evaluate_monitoring.py`
feeds distributions whose drift is known by construction and cohort splits whose
disparity is known by construction:

| Check | Result |
|---|---|
| Identical distributions → stable | PSI 0.011 ✅ |
| +15 mean shift → significant | PSI 3.13 ✅ |
| Variance collapse → significant | PSI 5.56 ✅ |
| Even split (0.30 vs 0.30) → no flag | ratio 1.00 ✅ |
| 3:1 disparity (0.60 vs 0.20) → flag | ratio 0.33 ✅ |
| Cohort of 3 → no rate emitted | `null` ✅ |
| **Total** | **9/9 passed** |

The live report on this deployment correctly says *insufficient data* for every
figure. That is the intended output at this scale.

**Files:** `engine/monitoring.py`, `evaluate_monitoring.py`,
`routes/admin_routes.py`, 15 profile JSONs (cohort block added, nothing removed),
`frontend/admin.{html,page.js}`.
**Tests:** `tests/test_monitoring.py` — 25.

---

## 14. Improvement #5 — Passkeys and recovery codes (IMPLEMENTED)

**Why this is the structural answer to SIM swap.** Every other factor in
SIMShield is delivered to a phone number, and a SIM swap steals the phone
number. That is not a weak OTP implementation — it is the OTP's threat model
being wrong for this attack. Both factors here are ones a successful swap does
not defeat.

**Recovery codes.** Ten single-use codes, PBKDF2-SHA-256 with per-code salt,
constant-time comparison, claimed atomically inside `BEGIN IMMEDIATE` so
concurrent requests cannot spend the same code (a racing-thread test proves
exactly one of ten wins). Base32 without I/O/0/1 and separator-insensitive,
because they are read off paper by someone mid-incident. `/api/auth/recovery-login`
replaces the OTP step — the password step still applies.

**WebAuthn.** Full registration and authentication ceremonies, hand-written
because no library is available in this environment. `cryptography` performs the
signature maths; nothing cryptographic is invented. The parsing is the risky
part, so `engine/cbor_min.py` is decode-only and strict: indefinite lengths,
tags, duplicate map keys, deep nesting, oversized declared lengths and trailing
bytes are all rejected rather than tolerated.

**Every check has its own negative test**, because one "invalid input is
rejected" test cannot tell you *which* check rejected it:

| Broken thing | Refused |
|---|---|
| Signature corrupted | ✅ |
| Signature from a different key (right credential id) | ✅ |
| Challenge not the one issued | ✅ |
| Challenge replayed | ✅ |
| Origin not on the allowlist | ✅ |
| RP ID hash for another site | ✅ |
| `webauthn.create` replayed as `webauthn.get` | ✅ |
| User-presence flag absent | ✅ |
| Credential belonging to another account | ✅ |
| Regressed signature counter | ⚠️ clone warning + critical alert |

**Stated limitations, not implied ones.** Attestation is parsed but **not
verified** — the authenticator model is not proven. This matches ordinary
consumer deployments but is a real limit, surfaced in the API response
(`attestation_verified: false`), in the user-facing posture, in the config
comment and in the UI. Passkeys also require HTTPS and a registered domain
outside localhost. A constant-zero signature counter is treated as normal, not
as a clone, because synced passkeys legitimately report it — refusing would lock
out ordinary iCloud/Google users.

**Files:** `engine/webauthn.py`, `engine/cbor_min.py`, `engine/recovery_codes.py`,
`routes/auth_routes.py`, `routes/user_routes.py`, `engine/db.py`
(`webauthn_credentials`, `recovery_codes`), `config.yaml` (`webauthn:`),
`frontend/defence.{html,page.js}`.
**Tests:** `tests/test_passkeys.py` — 84, including a synthetic authenticator
that produces genuine P-256/RSA keys, CBOR and signatures.

---

## 15. Bugs found by these tests (not pre-existing)

| Bug | How it surfaced | Fix |
|---|---|---|
| `redirect_audit` moved the log but not its checkpoints, so a redirected chain was verified against the main log's checkpoint and reported **truncation on an intact chain** | `test_the_audit_chain_still_verifies_with_staff_entries` | `_checkpoint_path()` follows the override |
| `feedback._rate` returned a rate while flagging it insufficient — the module docstring promised `null`, the code did not deliver it | `test_thin_data_reports_no_rate_at_all` | Rate and CI are `null` below the threshold |
| Aggregate-rate tests depended on which tests ran first | Order-dependent failure | `clean_slate` fixture isolates global-aggregate tests |

The middle one is worth noting for the same reason as correction C2: **the
documentation described a control the code did not implement.** It was caught
only because a test asserted on the promised behaviour rather than on the flag.

### Post-delivery self-review (found by asking "what did I not check?")

Four more defects were found by auditing the *frontend* and the *retention job*
— neither of which any Python API test exercises. All four are the C2 family
again: **a green suite over a broken surface.**

| # | Defect | Impact | Why nothing caught it |
|---|---|---|---|
| D1 | `sev-${severity}` builds a CSS class from a backend enum, but only `.sev-critical` existed — `low`/`medium`/`high` had no rule | Case-severity chips rendered `.sev`'s **white text on no background: invisible** | API tests assert JSON; `node --check` only proves the file parses; the CSP test only looks for inline scripts |
| D2 | `class="btn secondary"` — `.secondary` is defined nowhere (the real variants are `ghost`/`subtle`/`small`/`danger`) | "Remove" and "Withdraw" rendered as **full primary CTAs**, the most prominent thing on the page | Nothing compared emitted class names against the stylesheet |
| D3 | `appeals.purge_expired()` existed but `compliance.enforce_retention()` never called it; `cases`/`case_notes` had no retention at all | A retention window documented in `compliance.yaml` and **enforced by nothing** — a data-protection claim the system did not honour | The function had a unit test; nothing tested that the *job* invoked it |
| D4 | `.table-wrap` invented in new markup; the codebase convention is `.table-scroll` | Wide tables overflowed the page instead of scrolling in-container | No check that markup classes resolve |

**Fixes:** the three missing `.sev-*` rules added; `btn secondary` → `btn ghost`
(4 sites); retention extended to appeals, cases, case notes and spent recovery
codes — **resolved records only**, so an open case is never deleted from under
someone waiting for an answer; `.table-wrap` → the existing `.table-scroll`.

**The generalisable fix** is `tests/test_frontend_contract.py` (47 tests), which
asserts the join the previous suites had no view of:
- every CSS class the code can *construct* from a backend enum has a rule
  (parametrised over `cases.SEVERITIES`, so adding a severity fails the suite);
- no page invents a button variant the stylesheet does not define;
- every `<script src>` resolves, and every helper a page's script *calls* is
  defined by a script that page *actually loads* (`admin.html` does not load
  `shell.js`, so the check follows usage rather than assuming a fixed set);
- every element id a page script targets exists in the markup, excluding ids
  the script itself injects at runtime;
- documented limitations (attestation, synthetic cohorts) reach the UI, not
  just the docs.

Two of those tests initially failed on my *own* assertions being too crude
rather than on real defects (`renderShell` required of a page that never calls
it; dynamically-injected ids reported missing). Both were tightened rather than
deleted — a test that is wrong in the strict direction is still evidence, and
weakening it to green would have removed the check entirely.

### D5 — the detection page rendered blank (found by the user, not by me)

The most serious of the set, and the only one a reader would hit immediately.

**What happened.** During the P0 remediation I changed `/api/users` to return
`{"synthetic": true, "profiles": [...]}` instead of a bare list — a deliberate
honesty marker labelling the data as synthetic. Two page scripts still called
`users.map(...)`. `.map` is undefined on an object, so the load function threw;
and because `bootPage()` (which reveals the page) runs at the *end* of that
function, **`/detection` rendered completely blank** — the page the entire
detection story is demonstrated on. `/register`'s profile picker was silently
empty for the same reason.

**Why nothing caught it.** Every backend test asserted the endpoint's *content*
and passed. The CSP test found no inline scripts and passed. `node --check`
parsed the file and passed. Nothing anywhere compared the response's **shape**
to what the page did with it. An API response shape is part of its contract with
the page: changing it is a breaking change even when every backend test is green.

**Fix.** Both consumers now read `users.profiles || users`. The `synthetic`
marker stays — removing it would regress the honesty labelling it was added for.

**Test.** `TestApiShapeMatchesPageUsage` extracts every `getJSON(path)` in every
page script, pairs it with the variable holding the result, and — where the
script calls `.map()` on that variable — asserts the endpoint returns a JSON
array. A second test asserts no page calls an endpoint that 404s or 500s.

**A trap inside the fix.** The first version of that check passed even with the
bug deliberately reintroduced: its variable extraction only understood
`const x = await getJSON(...)`, and the real bug used
`const [groups, users] = await Promise.all([...])`. It would have shipped as a
safety net with a hole in exactly the shape of the defect it was written for.
Caught by reintroducing the bug and confirming the test *fails* — the same
vacuous-pass discipline that produced the isolating probes in §10. Both the
general check and a pinned regression test now fail on the reintroduced bug.

---

## 16. Scope correction — SIMShield is not a banking app

Raised by the user, and correct: the project had drifted into presenting itself
as a small bank. A page called *Money* offered a savings-account number, a
merchant field, quick-spend presets, a **Send money** button, a transfer history
and an explainer of four transaction-scoring rules.

**Why that was a real problem, not a cosmetic one.** None of it was the research
contribution, and all of it invited an examiner to evaluate SIMShield as
payments software — settlement, double-entry, PCI-DSS, and specifically the fact
that `balance` is a SQLite `REAL`. Every minute spent defending a simulated bank
is a minute not spent on SIM-swap detection. The thesis is a tool **for** digital
banking subscribers; it should sit alongside their bank, not impersonate one.

**What was kept, and why.** The cooling-off hold after a SIM change is not a
banking feature — it is a SIM-swap countermeasure, and the strongest available
answer to *"so what if a SIM is swapped?"*. The first large payment after a swap
is the drain pattern; the hold makes the payment neither refused nor allowed,
and the release goes through a channel the attacker does not hold. Deleting it
to tidy the scope would have removed a genuine contribution.

| Removed | Kept |
|---|---|
| Savings-account number, "Available balance" | Balance relabelled **"simulated funds at risk"** |
| Merchant field, quick-spend presets, "Send money" | A bare amount field, present only so the hold has something to act on |
| "Recent transfers" history | "Recent attempts", to show the hold working repeatedly |
| "How a transfer is judged" (four scoring rules) | The SIM-change rule, promoted to the page's headline |
| Nav label "Money" | Nav label **"Exposure"** |

**Data minimisation.** `merchant` and `category` are no longer accepted by
`POST /api/me/transactions` — detecting a SIM swap does not require knowing what
a subscriber buys, so it is not collected. A test asserts the API ignores them
even when a client sends them anyway.

**A defect found while doing this.** `balance` is a float, and repeated
subtraction drifts: 150000 − 0.1 × 1000 lands on 149899.99999999418. Rather than
migrate the schema mid-project, amounts are now constrained to **whole rupees**,
which puts every value well under 2^53 where IEEE-754 subtraction is exact — the
drift becomes unreachable rather than merely unlikely. A production ledger would
store integer paisa; that is now a stated simplification instead of an unstated
one.

**A worse defect found by that fix.** `Validator.number(integer=True)` used
`int(v)`, which **silently truncates**: a payment of 12.34 was executed as 12
with no error. That is a wrong answer presented as a right one, and it affected
every `integer=True` caller, not just money. The validator now rejects a
non-integral value rather than rounding on the user's behalf.

**Guarded by** `tests/test_scope_boundaries.py` (25 tests): the banking language
cannot return, the containment control cannot be deleted, the amount input stays
whole-rupee, the public config endpoint stays an allowlist that leaks no
detection thresholds, and the page's stated hold window is read from
`config.yaml` rather than hardcoded — so the copy cannot drift out of step with
the running system.

---

## 17. Deliberately NOT implemented

- **Controlled phishing-awareness experiment.** It involves **deception of human
  participants** and falls outside the existing ethics approval. It would need a
  new application, a debrief protocol and supervisor sign-off. Not started, and
  it should not be started inside the current approval.
- **Differential-privacy aggregate telemetry.** With ~20 study participants the
  noise required for a meaningful ε destroys the signal. Better as stated future
  work than as a chapter making a claim the sample cannot support.

---

### New, defensible claims this work earns
- A documented threat model with 6 attacker classes and 4 trust boundaries.
- 23 findings identified and 21 fully remediated, each with automated tests.
- Concurrency-safe financial simulation demonstrated by racing-thread tests.
- Integrity-verified ML artefact loading (deserialisation is RCE).
- Evaluation methodology with a genuinely held-out test set, ablations and an
  adversarial suite — including **one honestly-reported failing case**.
- A typed operator-integration boundary whose **fail-open property is measured
  across nine degradation modes**, not asserted — and whose evaluation harness
  was strengthened after it was found capable of passing vacuously.
- Human-in-the-loop review made **reviewable**: coded outcomes from a fixed
  taxonomy, with the outcome derived from the code so a resolution cannot
  contradict its own justification, and staff actions in the same
  tamper-evident chain as subscriber decisions.
- A false-positive rate derived from **human labels rather than the dataset
  generator** — the only accuracy figure in the project whose ground truth does
  not come from the process being evaluated — reported with its denominator and
  suppressed entirely below significance.
- Fairness and drift monitors **validated against ground truth known by
  construction** (9/9), rather than a dashboard asserted to work.
- A WebAuthn implementation where **each individual check has its own negative
  test**, and whose limitations (no attestation verification, HTTPS/RP-ID
  requirement) are surfaced in the API, the UI and the documentation.

/* defence.page.js — extracted from defence.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const g = (id) => el("#" + id);
    let USER = null, ZONES = [];

    renderShell("defence", "Defence", {
      links: [{ href: "/dashboard", label: "Dashboard" }, { href: "/money", label: "Exposure" }],
    });

    const sev = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;

    async function load() {
      let d;
      try { d = await getJSON("/api/me/dashboard"); }
      catch (_) { g("need-login").classList.remove("hidden"); bootPage(); return; }
      USER = d.user;
      g("main").style.display = "";

      /* freeze card */
      const frozen = USER.frozen;
      g("freeze-card").style.borderColor = frozen ? "var(--danger)" : "var(--hairline)";
      g("freeze-icon").innerHTML = icon(frozen ? "lock" : "snowflake", 26);
      g("freeze-icon").style.color = frozen ? "var(--danger)" : "var(--primary)";
      g("freeze-title").textContent = frozen ? "Account is frozen" : "Emergency freeze";
      g("freeze-desc").textContent = frozen
        ? "Every transaction is being refused. Unfreezing needs a one-time email code."
        : "Suspect something is wrong? Pause every transaction instantly. You can undo it with an emailed code.";
      g("freeze-action").innerHTML = frozen
        ? `<button class="ghost" id="btn-unfreeze">Request unfreeze code</button>`
        : `<button class="danger" id="btn-freeze">Freeze my account</button>`;

      const bf = g("btn-freeze"), bu = g("btn-unfreeze");
      if (bf) bf.addEventListener("click", async () => {
        if (!confirm("Freeze your account? Every transaction will be refused until you unfreeze.")) return;
        await postJSON("/api/me/freeze", {}); load();
      });
      if (bu) bu.addEventListener("click", async () => {
        const { ok, data } = await postJSON("/api/me/unfreeze/request", {});
        if (!ok) return;
        const code = data.delivery && data.delivery.demo && data.delivery.demo.otp;
        if (code) {
          g("freeze-demo-otp").innerHTML =
            `Demo outbox — unfreeze code <span class="mono" style="font-size:16px">${esc(code)}</span>`;
          g("freeze-demo-otp").classList.remove("hidden");
        }
        g("unfreeze-form").classList.remove("hidden");
        g("unfreeze-code").focus();
      });

      /* sign-in locations */
      const locs = d.login_locations || [];
      g("loc-list").innerHTML = locs.length ? locs.map((l) => `
        <div class="item">
          <div class="grow">
            <div class="title">${icon("pin", 15)} ${esc(l.area || "Unknown area")}${
              l.country ? `<span class="muted">, ${esc(l.country)}</span>` : ""}
              ${l.mismatch ? `<span class="sev sev-critical">SIM elsewhere</span>` : ""}</div>
            <div class="desc muted">${esc(l.band || "distance unknown")} from a safe zone${
              l.sim_area ? ` · operator placed your SIM near ${esc(l.sim_area)}` : ""}</div>
          </div>
          <div style="text-align:right">
            <div><span class="decision d-${esc(l.decision)}"
                 style="font-size:11px;padding:3px 10px">${esc(l.decision)}</span></div>
            <div class="when">${fmtWhen(l.created_at)}</div>
          </div>
        </div>`).join("")
        : `<div class="empty">${icon("pin", 30)}<p>No sign-in locations recorded yet.
             They appear here after you sign in with location sharing enabled.</p></div>`;

      /* sim events */
      g("sim-list").innerHTML = d.sim_events.length ? d.sim_events.map((s) => `
        <div class="item">
          <div class="grow">
            <div class="title">${esc(s.event_type.replace(/_/g, " "))}
              ${s.risk_score >= 60 ? sev("critical") : ""}</div>
            <div class="desc muted">${esc(s.details || "")}${s.operator ? " · " + esc(s.operator) : ""}</div>
          </div>
          <div class="when">${fmtWhen(s.occurred_at)}</div>
        </div>`).join("")
        : `<div class="empty">${icon("sim", 30)}<p>No SIM events recorded on your number.</p></div>`;

      /* devices */
      g("device-list").innerHTML = d.devices.length ? d.devices.map((v) => `
        <div class="item"><div class="grow">
          <div class="title">${esc(v.label || "Device")}
            <span class="mono">${esc(v.device_id)}</span></div>
          <div class="desc muted">first seen ${fmtWhen(v.first_seen)}</div>
        </div><div class="when">last ${fmtWhen(v.last_seen)}</div></div>`).join("")
        : `<div class="empty">${icon("phone", 28)}<p>No devices yet.</p></div>`;

      /* sessions */
      g("session-list").innerHTML = d.sessions.map((s) => `
        <div class="item"><div class="grow">
          <div class="title">${s.current ? "This device" : "Session"}
            <span class="mono">${esc(s.session_id)}</span>
            ${s.current ? `<span class="status-chip">current</span>` : ""}</div>
          <div class="desc muted">since ${fmtWhen(s.created_at)} · IP ${esc(s.ip || "unknown")}</div>
        </div>${s.current ? "" :
          `<button class="subtle small" data-revoke="${esc(s.session_id)}">Revoke</button>`}</div>`).join("");
      g("session-list").querySelectorAll("[data-revoke]").forEach((b) =>
        b.addEventListener("click", async () => {
          await postJSON(`/api/me/sessions/${b.dataset.revoke}/revoke`, {}); load();
        }));

      /* zones + prefs */
      ZONES = USER.safe_zones || [];
      renderZones();
      g("pref-email").checked = USER.prefs.email !== false;
      g("pref-sms").checked = USER.prefs.sms !== false;
      g("pref-push").checked = USER.prefs.push === true;
      g("pref-lang").value = USER.language || "en";
      g("trusted-now").textContent = USER.trusted_contact_masked
        ? `Currently set to ${USER.trusted_contact_masked} — stored encrypted.`
        : "No trusted contact set yet.";
      renderPushState();

      g("activity-list").innerHTML = d.activity.map((a) => `
        <div class="item"><div class="grow"><div class="desc">${esc(a.action.replace(/_/g, " "))}</div></div>
        <div class="when">${fmtWhen(a.created_at)}</div></div>`).join("");

      bootPage();
    }

    /* --- zones --------------------------------------------------------------- */
    function renderZones() {
      g("zone-list").innerHTML = ZONES.length ? ZONES.map((z, i) => `
        <div class="flag"><span>${icon("pin", 15)} ${esc(z.name)}
          <span class="muted">${z.lat.toFixed(3)}, ${z.lon.toFixed(3)}</span></span>
          <button class="subtle small" data-zdel="${i}" aria-label="Remove ${esc(z.name)}">Remove</button>
        </div>`).join("")
        : `<p class="small muted">No zones yet — the default Kathmandu Valley zones are used.</p>`;
      g("zone-list").querySelectorAll("[data-zdel]").forEach((b) =>
        b.addEventListener("click", () => { ZONES.splice(+b.dataset.zdel, 1); renderZones(); }));
    }
    g("btn-zone-add").addEventListener("click", () => {
      const v = g("zone-preset").value;
      if (!v) return;
      if (ZONES.length >= 5) { alert("You can save up to 5 safe zones."); return; }
      const [name, lat, lon] = v.split("|");
      if (ZONES.some((z) => z.name === name)) return;
      ZONES.push({ name, lat: parseFloat(lat), lon: parseFloat(lon) });
      renderZones();
    });
    g("btn-zones-save").addEventListener("click", async () => {
      const { ok } = await postJSON("/api/me/safezones", { zones: ZONES }, "PUT");
      if (ok) flash("zones-saved");
    });

    /* --- prefs + push -------------------------------------------------------- */
    function flash(id) {
      g(id).classList.remove("hidden");
      setTimeout(() => g(id).classList.add("hidden"), 2000);
    }
    function renderPushState() {
      const supported = "Notification" in window;
      const granted = supported && Notification.permission === "granted";
      const denied = supported && Notification.permission === "denied";
      const wants = g("pref-push").checked;
      g("push-state").textContent = !supported ? "Not supported here."
        : granted ? "Allowed." : denied ? "Blocked in browser settings."
        : wants ? "Permission still needed." : "";
      g("push-enable-row").classList.toggle("hidden", !supported || granted || denied || !wants);
    }
    g("pref-push").addEventListener("change", renderPushState);
    g("btn-push-enable").addEventListener("click", async () => {
      const r = await window.simshieldEnablePush();
      g("push-msg").textContent = r.ok ? "enabled" : (r.error || "failed");
      renderPushState();
    });
    g("btn-prefs").addEventListener("click", async () => {
      const body = {
        email: g("pref-email").checked, sms: g("pref-sms").checked,
        push: g("pref-push").checked, language: g("pref-lang").value,
      };
      const tc = g("pref-trusted").value.trim();
      if (tc || USER.trusted_contact_masked) body.trusted_contact = tc;
      const { ok } = await postJSON("/api/me/prefs", body, "PUT");
      if (ok) { flash("prefs-saved"); g("pref-trusted").value = ""; load(); }
    });

    g("btn-unfreeze-confirm").addEventListener("click", async () => {
      const { ok, data } = await postJSON("/api/me/unfreeze/confirm",
        { code: g("unfreeze-code").value.trim() });
      if (!ok) {
        g("freeze-err").textContent = data.error || "Failed.";
        g("freeze-err").classList.remove("hidden");
        return;
      }
      g("freeze-err").classList.add("hidden");
      g("unfreeze-form").classList.add("hidden");
      load();
    });

    /* ------------------------------------------------------------------
     * Phone-independent factors: passkeys + recovery codes (improvement #5)
     * ------------------------------------------------------------------ */
    const b64urlToBuf = (s) => {
      const pad = s.replace(/-/g, "+").replace(/_/g, "/");
      const raw = atob(pad + "=".repeat((4 - (pad.length % 4)) % 4));
      return Uint8Array.from(raw, (c) => c.charCodeAt(0));
    };
    const bufToB64url = (buf) =>
      btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    async function loadFactors() {
      let f;
      try { f = await getJSON("/api/me/security/factors"); } catch (_) { return; }

      g("factors-advice").textContent = f.advice;
      g("factors-advice").style.color =
        f.sim_swap_resistant ? "var(--primary)" : "var(--danger)";

      g("passkey-list").innerHTML = f.credentials.length
        ? f.credentials.map((c) => `
            <div class="row" style="justify-content:space-between;align-items:center;
                 padding:8px 0;border-bottom:1px solid var(--hairline)">
              <div>
                <div style="font-weight:600">${esc(c.label || "Passkey")}</div>
                <div class="small muted">Added ${esc((c.created_at || "").slice(0, 10))}${
                  c.last_used_at ? " · last used " + esc(c.last_used_at.slice(0, 10)) : ""
                }</div>
              </div>
              <button class="btn ghost" data-remove-passkey="${c.id}"
                      type="button">Remove</button>
            </div>`).join("")
        : `<p class="small muted">No passkeys yet.</p>`;

      g("passkey-list").querySelectorAll("[data-remove-passkey]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          await postJSON(`/api/me/passkeys/${btn.getAttribute("data-remove-passkey")}`,
                         {}, "DELETE");
          loadFactors();
        });
      });

      const rc = f.recovery_codes;
      g("recovery-status").textContent = rc.configured
        ? `${rc.remaining} of ${rc.total} codes remaining.` +
          (rc.low ? " Running low — generate a new set." : "")
        : "No recovery codes yet.";
      g("recovery-status").style.color = rc.low ? "var(--danger)" : "";

      // WebAuthn needs a secure context. Say so plainly rather than letting the
      // button fail silently on an insecure origin.
      if (!window.PublicKeyCredential) {
        g("add-passkey").disabled = true;
        g("passkey-msg").textContent =
          "This browser does not support passkeys, or this page is not on a secure origin.";
      }
    }

    g("add-passkey").addEventListener("click", async () => {
      const msg = g("passkey-msg");
      msg.textContent = "Waiting for your device…";
      try {
        const { ok: gotOpts, data: opts } =
          await postJSON("/api/me/passkeys/register/options", {});
        if (!gotOpts) throw new Error(opts.error || "Could not start enrolment.");

        const pk = opts.publicKey;
        pk.challenge = b64urlToBuf(pk.challenge);
        pk.user.id = b64urlToBuf(pk.user.id);
        (pk.excludeCredentials || []).forEach((c) => { c.id = b64urlToBuf(c.id); });

        const cred = await navigator.credentials.create({ publicKey: pk });
        const { ok, data } = await postJSON("/api/me/passkeys/register", {
          handle: opts.handle,
          label: "This device",
          credential: {
            id: cred.id,
            response: {
              clientDataJSON: bufToB64url(cred.response.clientDataJSON),
              attestationObject: bufToB64url(cred.response.attestationObject),
            },
          },
        });
        msg.textContent = ok ? "Passkey added." : (data.error || "Could not add it.");
        if (ok) loadFactors();
      } catch (e) {
        msg.textContent = e.message || "Your device cancelled the request.";
      }
    });

    g("gen-recovery").addEventListener("click", async () => {
      const { ok, data } = await postJSON("/api/me/recovery-codes", {});
      if (!ok) return;
      g("recovery-codes").classList.remove("hidden");
      g("recovery-list").textContent = data.codes.join("\n");
      loadFactors();
    });

    /* ------------------------------------------------------------------
     * Appeals (improvement #3)
     * ------------------------------------------------------------------ */
    const APPEAL_LABEL = {
      submitted: "Waiting for review", reviewing: "An analyst is looking at it",
      upheld: "Upheld — we agree the decision was wrong",
      rejected: "Reviewed — the original decision stands",
      withdrawn: "Withdrawn by you",
    };
    let APPEALABLE = null;

    async function loadAppeals() {
      let a;
      try { a = await getJSON("/api/me/appeals"); } catch (_) { return; }
      APPEALABLE = a.appealable;

      g("appealable-box").innerHTML = a.appealable
        ? `<p class="small" style="margin:0">Your most recent sign-in check was
             <strong>${esc(a.appealable.decision)}</strong>
             (risk ${esc(a.appealable.risk_score)}) on
             ${esc((a.appealable.when || "").slice(0, 16).replace("T", " "))}.</p>`
        : `<p class="small muted" style="margin:0">Nothing recent to appeal — your
             last sign-in check did not restrict anything.</p>`;

      g("appeal-list").innerHTML = a.appeals.length
        ? `<h3 style="margin:0 0 6px;font-size:15px">Your appeals</h3>` +
          a.appeals.map((ap) => `
            <div style="padding:8px 0;border-bottom:1px solid var(--hairline)">
              <div class="row" style="justify-content:space-between;gap:8px">
                <span class="small" style="font-weight:600">
                  ${esc(ap.decision || "decision")} ·
                  ${esc((ap.created_at || "").slice(0, 10))}
                </span>
                <span class="small muted">${esc(APPEAL_LABEL[ap.status] || ap.status)}</span>
              </div>
              <div class="small muted">${esc(ap.statement)}</div>
              ${ap.outcome_note ? `<div class="small">Reviewer: ${esc(ap.outcome_note)}</div>` : ""}
              ${["submitted", "reviewing"].includes(ap.status)
                  ? `<button class="btn ghost" data-withdraw="${ap.id}"
                             type="button" style="margin-top:6px">Withdraw</button>` : ""}
            </div>`).join("")
        : "";

      g("appeal-list").querySelectorAll("[data-withdraw]").forEach((btn) => {
        btn.addEventListener("click", async () => {
          await postJSON(`/api/me/appeals/${btn.getAttribute("data-withdraw")}/withdraw`, {});
          loadAppeals();
        });
      });
    }

    g("submit-appeal").addEventListener("click", async () => {
      const msg = g("appeal-msg");
      const payload = { statement: g("appeal-statement").value.trim() };
      if (APPEALABLE) {
        payload.decision = APPEALABLE.decision;
        payload.risk_score = APPEALABLE.risk_score;
      }
      const { ok, data } = await postJSON("/api/me/appeals", payload);
      msg.textContent = ok
        ? "Thank you — an analyst will review this."
        : (data.error || "Could not submit.");
      msg.style.color = ok ? "" : "var(--danger)";
      if (ok) { g("appeal-statement").value = ""; loadAppeals(); }
    });

    load();
    loadFactors();
    loadAppeals();
  

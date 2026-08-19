/* admin.page.js — extracted from admin.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const g = (id) => el("#" + id);
    const sev = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;

    const kpi = (num, lbl) =>
      `<div class="card kpi"><div class="num">${num}</div><div class="lbl">${lbl}</div></div>`;

    async function load() {
      initNav();
      let ov;
      try { ov = await getJSON("/api/admin/overview"); }
      catch (_) { g("need-admin").classList.remove("hidden"); return; }
      g("main").style.display = "";

      g("kpis").innerHTML =
        kpi(ov.users, "Subscribers") +
        kpi(ov.alerts_open, "Open alerts") +
        kpi(ov.alerts_critical, "Critical open") +
        kpi(ov.escalations, "Escalations") +
        kpi(ov.flagged_transactions, "Flagged transactions") +
        kpi(ov.sim_events_30d, "SIM events (30 d)") +
        kpi(ov.frozen_accounts, "Frozen accounts") +
        kpi(ov.chat_messages, "Chat messages");

      const a = ov.audit;
      g("audit-banner").className = "banner " + (a.intact ? "okay" : "error");
      g("audit-banner").innerHTML = icon(a.intact ? "lock" : "alert", 16) + " " + esc(a.message) +
        ` (${a.entries} hash-chained audit entries)`;

      loadAlerts();
      loadUsers();
      loadSide();
      loadStats();
    }

    async function loadStats() {
      const s = await getJSON("/api/admin/stats");
      const days = s.alerts_per_day || [];
      const maxN = Math.max(1, ...days.map((d) => d.n));
      g("chart-days").innerHTML = days.length ? days.map((d) => `
        <div class="bar"><div class="lbl"><span>${esc(d.day)}</span>
          <span>${d.n} total · ${d.critical} critical</span></div>
          <div class="track"><span style="width:${(d.n / maxN * 100).toFixed(0)}%"></span></div>
        </div>`).join("") : `<p class="small muted">No alerts in the last 7 days.</p>`;

      const dec = (s.pre_otp_decisions || []).filter((d) => d.decision);
      const maxD = Math.max(1, ...dec.map((d) => d.n));
      g("chart-decisions").innerHTML = dec.length ? dec.map((d) => `
        <div class="bar"><div class="lbl"><span><span class="decision d-${esc(d.decision)}"
          style="font-size:11px;padding:2px 10px">${esc(d.decision)}</span></span>
          <span>${d.n}</span></div>
          <div class="track"><span style="width:${(d.n / maxD * 100).toFixed(0)}%;
            background:${DEC_COLOR[d.decision] || "var(--primary)"}"></span></div>
        </div>`).join("") : `<p class="small muted">No pre-OTP checks recorded yet.</p>`;

      const t = s.transactions || {};
      g("txn-summary").textContent =
        `Transactions: ${t.total ?? 0} total · ${t.flagged ?? 0} flagged · ${t.held ?? 0} on hold.`;
    }

    const KIND_ICON = {
      alert: icon("bell", 16), sim_event: icon("sim", 16),
      transaction: icon("wallet", 16), activity: icon("clock", 16),
    };
    async function openTimeline(id) {
      const t = await getJSON(`/api/admin/users/${id}/timeline`);
      g("timeline-card").classList.remove("hidden");
      g("timeline-title").textContent =
        `Case timeline — ${t.user.display_name} (${t.user.email})` +
        (t.user.frozen ? " · FROZEN" : "");
      g("timeline-list").innerHTML = t.events.map((e) => `
        <div class="item"><div class="grow">
          <div class="desc">${KIND_ICON[e.kind] || "•"} ${esc(e.label)}</div>
        </div><div class="when">${fmtWhen(e.when)}</div></div>`).join("");
      g("timeline-card").scrollIntoView({ behavior: "smooth" });
    }
    g("timeline-close").addEventListener("click", () =>
      g("timeline-card").classList.add("hidden"));

    async function loadAlerts() {
      const st = g("filter-status").value;
      const rows = await getJSON("/api/admin/alerts" + (st ? "?status=" + st : ""));
      g("alert-rows").innerHTML = rows.length ? rows.map((r) => `
        <tr>
          <td>${fmtWhen(r.created_at)}</td>
          <td>${esc(r.display_name || "—")}<br /><span class="muted">${esc(r.email || "")}</span></td>
          <td>${esc(r.alert_type)}</td>
          <td>${sev(r.severity)}</td>
          <td style="max-width:340px">${esc(r.message)}</td>
          <td><span class="status-chip">${esc(r.status)}</span></td>
          <td style="white-space:nowrap">
            ${r.status !== "resolved" ? `<button class="subtle small" data-act="resolved" data-id="${r.id}">Resolve</button>` : ""}
            ${r.status === "new" ? `<button class="subtle small" data-act="escalated" data-id="${r.id}">Escalate</button>` : ""}
          </td>
        </tr>`).join("")
        : `<tr><td colspan="7" class="muted">No alerts for this filter.</td></tr>`;
      g("alert-rows").querySelectorAll("[data-act]").forEach((b) =>
        b.addEventListener("click", async () => {
          await postJSON(`/api/admin/alerts/${b.dataset.id}/status`, { status: b.dataset.act });
          loadAlerts(); load();
        }));
    }

    async function loadUsers() {
      const rows = await getJSON("/api/admin/users");
      g("user-rows").innerHTML = rows.map((u) => `
        <tr data-user="${u.id}" style="cursor:pointer">
          <td>${u.id}</td>
          <td>${esc(u.display_name)}${u.role === "admin" ? ` <span class="status-chip">admin</span>` : ""}</td>
          <td>${esc(u.email)}</td>
          <td>${esc(u.operator || "—")}</td>
          <td>${u.points}</td>
          <td>${u.open_alerts ? `<b style="color:var(--danger)">${u.open_alerts}</b>` : "0"}</td>
          <td>${fmtWhen(u.last_login) || "—"}</td>
          <td>${u.frozen ? `<span class="sev sev-critical">frozen</span>` : `<span class="status-chip">active</span>`}</td>
          <td>${u.role !== "admin" ? `<button class="subtle small" data-freeze="${u.id}" data-to="${u.frozen ? 0 : 1}">
                ${u.frozen ? "Unfreeze" : "Freeze"}</button>` : ""}</td>
        </tr>`).join("");
      g("user-rows").querySelectorAll("[data-freeze]").forEach((b) =>
        b.addEventListener("click", async (e) => {
          e.stopPropagation();
          await postJSON(`/api/admin/users/${b.dataset.freeze}/freeze`,
                         { frozen: b.dataset.to === "1" });
          loadUsers(); load();
        }));
      g("user-rows").querySelectorAll("tr[data-user]").forEach((tr) =>
        tr.addEventListener("click", () => openTimeline(tr.dataset.user)));
    }

    async function loadSide() {
      const ob = await getJSON("/api/admin/outbox");
      g("outbox-rows").innerHTML = ob.map((o) => `
        <tr><td>${fmtWhen(o.created_at)}</td><td>${esc(o.channel)}</td>
        <td>${esc(o.to_masked || "")}</td><td style="max-width:220px">${esc(o.subject || "")}</td>
        <td><span class="status-chip">${esc(o.status)}</span></td></tr>`).join("");
      const cl = await getJSON("/api/admin/chatlogs");
      g("chat-rows").innerHTML = cl.map((c) => `
        <tr><td>${fmtWhen(c.created_at)}</td><td>${esc(c.email || "anonymous")}</td>
        <td>${esc(c.lang)}</td><td style="max-width:220px">${esc(c.query)}</td>
        <td>${esc(c.intent)}${c.escalated ? " " + icon("alert", 15) : ""}</td></tr>`).join("");
    }

    /* ==================================================================
     * Case queue with reason codes (improvement #2)
     * ================================================================== */
    let TAXONOMY = null, CURRENT_CASE = null, CURRENT_APPEAL = null;

    async function loadTaxonomy() {
      if (!TAXONOMY) TAXONOMY = await getJSON("/api/admin/reason-codes");
      return TAXONOMY;
    }

    const codeOptions = (filter) => TAXONOMY.codes
      .filter(filter || (() => true))
      .map((c) => `<option value="${esc(c.code)}">${esc(c.code)} — ${esc(c.label)}</option>`)
      .join("");

    async function loadCases() {
      await loadTaxonomy();
      const status = g("filter-case-status").value;
      const d = await getJSON("/api/admin/cases" + (status ? `?status=${status}` : ""));

      const s = d.stats;
      g("case-stats").innerHTML = [
        ["Open", s.open_total], ["Overdue", s.overdue],
        ["Resolved", Object.values(s.by_outcome).reduce((a, b) => a + b, 0)],
        ["Median hours to resolve", s.median_hours_to_resolve ?? "—"],
      ].map(([label, value]) => `
        <div><div class="small muted">${esc(label)}</div>
        <div style="font-size:20px;font-weight:650">${esc(value)}</div></div>`).join("");

      g("case-rows").innerHTML = d.cases.map((c) => `
        <tr>
          <td>${fmtWhen(c.created_at)}</td>
          <td>${esc(c.display_name || c.email || "—")}</td>
          <td>${esc(c.title)}</td>
          <td><span class="sev sev-${esc(c.severity)}">${esc(c.severity)}</span></td>
          <td><span class="status-chip">${esc(c.status)}</span>${
            c.overdue ? ' <span class="sev sev-critical">overdue</span>' : ""}</td>
          <td>${c.reason_code
                ? `${esc(c.outcome)} <span class="small muted">(${esc(c.reason_code)})</span>`
                : "—"}</td>
          <td><button class="subtle small" data-case="${c.id}" type="button">Open</button></td>
        </tr>`).join("") || `<tr><td colspan="7" class="small muted">No cases.</td></tr>`;

      g("case-rows").querySelectorAll("[data-case]").forEach((btn) => {
        btn.addEventListener("click", () => openCase(btn.getAttribute("data-case")));
      });
    }

    async function openCase(caseId) {
      const d = await getJSON(`/api/admin/cases/${caseId}`);
      CURRENT_CASE = d.case;
      g("case-detail").classList.remove("hidden");
      g("case-title").textContent = `Case #${d.case.id}: ${d.case.title}`;
      g("case-meta").textContent =
        `${d.case.severity} · ${d.case.status} · opened ${d.case.created_at}` +
        (d.case.due_at ? ` · due ${d.case.due_at}` : "") +
        (d.case.decision ? ` · detector said ${d.case.decision} (${d.case.risk_score})` : "");

      g("case-notes").innerHTML = d.notes.map((n) => `
        <div style="padding:6px 0;border-bottom:1px solid var(--hairline)">
          <div class="small muted">${fmtWhen(n.created_at)} ·
            ${esc(n.author_name || "system")} · ${esc(n.kind)}</div>
          <div class="small" style="white-space:pre-wrap">${esc(n.body)}</div>
        </div>`).join("") || `<p class="small muted">No notes yet.</p>`;

      g("case-reason").innerHTML = codeOptions();
      showReasonHelp();
      g("case-resolve-form").style.display = d.case.status === "resolved" ? "none" : "";
      g("case-msg").textContent = "";
      g("case-detail").scrollIntoView({ behavior: "smooth", block: "nearest" });
    }

    function showReasonHelp() {
      const code = g("case-reason").value;
      const spec = TAXONOMY.codes.find((c) => c.code === code);
      if (!spec) return;
      g("case-reason-help").textContent =
        `${spec.guidance} → records outcome "${spec.outcome}"` +
        (spec.requires_evidence ? " · evidence required" : "") +
        (spec.counts_as_false_positive ? " · counts against detector accuracy" : "");
    }

    g("case-reason").addEventListener("change", showReasonHelp);
    g("case-close").addEventListener("click",
      () => g("case-detail").classList.add("hidden"));
    g("filter-case-status").addEventListener("change", loadCases);

    g("case-resolve").addEventListener("click", async () => {
      const { ok, data } = await postJSON(`/api/admin/cases/${CURRENT_CASE.id}/resolve`, {
        reason_code: g("case-reason").value,
        evidence: g("case-evidence").value.trim(),
      });
      g("case-msg").textContent = ok
        ? `Resolved as ${data.outcome}.` : (data.error || "Could not resolve.");
      g("case-msg").style.color = ok ? "" : "var(--danger)";
      if (ok) { g("case-evidence").value = ""; openCase(CURRENT_CASE.id); loadCases(); loadMonitoring(); }
    });

    g("case-investigating").addEventListener("click", async () => {
      const { ok, data } = await postJSON(`/api/admin/cases/${CURRENT_CASE.id}/status`,
        { status: "investigating" });
      g("case-msg").textContent = ok ? "Marked investigating." : (data.error || "Failed.");
      if (ok) { openCase(CURRENT_CASE.id); loadCases(); }
    });

    /* ==================================================================
     * Appeals queue (improvement #3)
     * ================================================================== */
    const APPEAL_STATE = {
      submitted: "Waiting", reviewing: "In review", upheld: "Upheld",
      rejected: "Rejected", withdrawn: "Withdrawn",
    };

    async function loadAppeals() {
      await loadTaxonomy();
      const d = await getJSON("/api/admin/appeals");
      g("appeal-rows").innerHTML = d.appeals.map((a) => `
        <tr>
          <td>${fmtWhen(a.created_at)}</td>
          <td>${esc(a.display_name || a.email || "—")}</td>
          <td>${esc(a.decision || "—")} ${a.risk_score != null
              ? `<span class="small muted">(${esc(a.risk_score)})</span>` : ""}</td>
          <td style="max-width:280px">${esc(a.statement)}</td>
          <td><span class="status-chip">${esc(APPEAL_STATE[a.status] || a.status)}</span></td>
          <td>${["submitted", "reviewing"].includes(a.status)
              ? `<button class="subtle small" data-appeal="${a.id}" type="button">Review</button>`
              : `<span class="small muted">${esc(a.outcome_note || "")}</span>`}</td>
        </tr>`).join("") || `<tr><td colspan="6" class="small muted">No appeals.</td></tr>`;

      g("appeal-rows").querySelectorAll("[data-appeal]").forEach((btn) => {
        btn.addEventListener("click", () => {
          CURRENT_APPEAL = btn.getAttribute("data-appeal");
          const row = d.appeals.find((a) => String(a.id) === CURRENT_APPEAL);
          g("appeal-review").classList.remove("hidden");
          g("appeal-review-title").textContent =
            `Appeal #${CURRENT_APPEAL} — ${row.display_name || row.email}`;
          syncAppealCodes();
          g("appeal-review-msg").textContent = "";
        });
      });
    }

    function syncAppealCodes() {
      // The code list follows the decision, so a contradictory pairing cannot
      // even be selected. The server refuses it too — this is convenience, not
      // the control.
      const uphold = g("appeal-decision").value === "uphold";
      g("appeal-reason").innerHTML = codeOptions(
        (c) => Boolean(c.counts_as_false_positive) === uphold);
    }

    g("appeal-decision").addEventListener("change", syncAppealCodes);

    g("appeal-submit").addEventListener("click", async () => {
      const { ok, data } = await postJSON(
        `/api/admin/appeals/${CURRENT_APPEAL}/review`, {
          uphold: g("appeal-decision").value === "uphold",
          reason_code: g("appeal-reason").value,
          evidence: g("appeal-evidence").value.trim(),
        });
      g("appeal-review-msg").textContent = ok
        ? `Recorded as ${data.status}.` : (data.error || "Could not record.");
      g("appeal-review-msg").style.color = ok ? "" : "var(--danger)";
      if (ok) {
        g("appeal-evidence").value = "";
        g("appeal-review").classList.add("hidden");
        loadAppeals(); loadCases(); loadMonitoring();
      }
    });

    /* ==================================================================
     * Drift & fairness monitoring (improvement #4)
     * ================================================================== */
    const pct = (v) => (v == null ? "—" : (v * 100).toFixed(1) + "%");

    async function loadMonitoring() {
      const m = await getJSON("/api/admin/monitoring");
      g("monitoring-warning").textContent = m.fairness.warning;

      const psi = m.drift.risk_score_psi;
      const mix = m.drift.decision_mix;
      g("monitoring-tiles").innerHTML = [
        ["Risk-score PSI", psi.psi ?? "—", psi.band],
        ["Recent scores", psi.recent_n, `reference ${psi.reference_n}`],
        ["Decision mix", mix.sufficient ? "comparable" : "insufficient",
         `${mix.recent.total} recent`],
      ].map(([label, value, sub]) => `
        <div class="card" style="margin:0">
          <div class="small muted">${esc(label)}</div>
          <div style="font-size:22px;font-weight:650">${esc(value)}</div>
          <div class="small muted">${esc(sub)}</div>
        </div>`).join("");

      const fpr = m.feedback.measured_false_positive_rate;
      const o = fpr.overall;
      g("fpr-box").innerHTML = `
        <p class="small" style="margin:0">
          ${o.sufficient
            ? `<strong>${pct(o.rate)}</strong> of ${o.total} reviewed restrictive
               decisions were coded as false positives
               (95% CI ${pct(o.ci95[0])}–${pct(o.ci95[1])}).`
            : `<strong>No rate reported.</strong> ${esc(o.note || "")}
               ${o.count} of ${o.total} reviewed so far.`}
        </p>
        <p class="small muted" style="margin:6px 0 0">${esc(fpr.caveats.join(" "))}</p>`;

      g("fairness-box").innerHTML = Object.entries(m.fairness.dimensions)
        .map(([dim, data]) => {
          const rows = Object.entries(data.cohorts).map(([name, c]) => `
            <tr><td>${esc(name)}</td><td>${esc(c.n)}</td>
            <td>${c.sufficient ? pct(c.selection_rate)
                 : `<span class="small muted">too few</span>`}</td></tr>`).join("");
          const di = data.disparate_impact;
          return `
            <div style="margin-bottom:14px">
              <div class="row" style="gap:8px">
                <strong class="small">${esc(dim)}</strong>
                <span class="small muted">${di.ratio == null
                  ? esc(di.note || "not comparable")
                  : `four-fifths ratio ${di.ratio}`}</span>
                ${di.flag ? '<span class="sev sev-critical">disparity flagged</span>' : ""}
              </div>
              <div class="table-scroll"><table>
                <thead><tr><th>Cohort</th><th>n</th><th>Restricted</th></tr></thead>
                <tbody>${rows}</tbody></table></div>
            </div>`;
        }).join("");
    }

    g("filter-status").addEventListener("change", loadAlerts);
    load();
    loadCases();
    loadAppeals();
    loadMonitoring();
    window.addEventListener('load', () => hydrateIcons());
  

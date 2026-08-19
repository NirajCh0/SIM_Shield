/* detection.page.js — extracted from detection.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    let SCENARIOS = [];
    const g = (id) => el("#" + id);

    renderShell("detection", "Detection demo", {
      tabs: false,
      links: [{ href: "/study", label: "User study" }, { href: "/metrics", label: "Evaluation" }],
      cta: { href: "/register", label: "Create account" },
    });

    async function load() {
      const [groups, users] = await Promise.all([
        getJSON("/api/scenarios/grouped"), getJSON("/api/users")]);
      // Flatten for indexing, but render grouped so the picker teaches the
      // four decision classes rather than showing one long list.
      SCENARIOS = [];
      let html = `<option value="">— custom —</option>`;
      groups.forEach((grp) => {
        html += `<optgroup label="${esc(grp.decision)} — ${esc(grp.label)}">`;
        grp.scenarios.forEach((s) => {
          html += `<option value="${SCENARIOS.length}">${esc(s.name)}</option>`;
          SCENARIOS.push(s);
        });
        html += `</optgroup>`;
      });
      g("scenario").innerHTML = html;
      // /api/users returns { synthetic: true, profiles: [...] } — the wrapper
      // labels the data as synthetic, which is a deliberate honesty marker. The
      // fallback keeps this working if the endpoint is ever a bare list again.
      const profiles = users.profiles || users;
      g("user").innerHTML = profiles.map((u) =>
        `<option value="${u.user_id}">${esc(u.display_name)} (${esc(u.operator)}, SIM ${u.sim_activation_date})</option>`).join("");
      // open on the headline fraud case
      const idx = SCENARIOS.findIndex((s) => s.name === "SIM-swap fraud, abroad");
      g("scenario").value = String(idx >= 0 ? idx : 0);
      applyScenario();
      bootPage();
    }

    function applyScenario() {
      const i = g("scenario").value;
      if (i === "") { g("scenario-note").textContent = ""; return; }
      const s = SCENARIOS[i], a = s.attempt;
      g("scenario-note").innerHTML =
        `Expected: <b>${esc(s.expected_decision)}</b>${s.note ? " — " + esc(s.note) : ""}`;
      g("user").value = s.user_id;
      g("lat").value = a.current_location.lat; g("lon").value = a.current_location.lon;
      g("imei").value = a.imei || "";
      g("logins").value = a.logins_last_24h ?? 1; g("failed").value = a.failed_logins_last_24h ?? 0;
      g("imsi").checked = !!a.imsi_change_flag; g("iccid").checked = !!a.iccid_change_flag;
      g("ipc").checked = !!a.ip_change_flag;
    }

    async function run() {
      const body = {
        user_id: g("user").value,
        current_location: { lat: parseFloat(g("lat").value), lon: parseFloat(g("lon").value) },
        imei: g("imei").value,
        timestamp: "2026-07-05T09:00:00+05:45",
        logins_last_24h: parseInt(g("logins").value || 0),
        failed_logins_last_24h: parseInt(g("failed").value || 0),
        imsi_change_flag: g("imsi").checked ? 1 : 0,
        iccid_change_flag: g("iccid").checked ? 1 : 0,
        ip_change_flag: g("ipc").checked ? 1 : 0,
      };
      const { ok, data } = await postJSON("/api/score", body);
      if (!ok) { alert(data.error || "Scoring failed"); return; }
      render(data);
    }

    function render(r) {
      g("empty").classList.add("hidden"); g("result").classList.remove("hidden");
      const d = g("decision"); d.textContent = r.decision; d.className = "decision d-" + r.decision;
      g("score").textContent = r.risk_score;
      const gg = g("gauge");
      gg.style.width = r.risk_score + "%";
      gg.style.background = DEC_COLOR[r.decision];
      g("mlflag").textContent = r.ml_used ? "ML model active" : "rules-only mode";

      g("reasons").innerHTML = r.reasons.map((x) => `<li>${esc(x)}</li>`).join("");

      const b = r.breakdown, w = b.fusion_weights;
      const rows = [
        ["Rule engine (SIM + location)", b.rule.score, w.rule_score],
        ["Behavioural signals", b.behavioral.score, w.behavioral_score],
      ];
      if (b.ml && b.ml.score != null) rows.push(["Random Forest — P(fraud)", b.ml.score, w.ml_score]);
      if (b.anomaly && b.anomaly.score != null)
        rows.push(["Isolation Forest — anomaly", b.anomaly.score, w.anomaly_score]);
      g("bars").innerHTML = rows.map(([lbl, val, weight]) => `
        <div class="bar"><div class="lbl">
          <span>${esc(lbl)} <span class="muted">· weight ${weight ?? "—"}</span></span>
          <span>${val}</span></div>
          <div class="track"><span style="width:${val}%"></span></div></div>`).join("");

      const flags = b.behavioral.flags || [];
      g("flags").innerHTML = flags.length
        ? flags.map((f) => `<div class="flag"><span>${esc(f.label)}</span><b>+${f.points}</b></div>`).join("")
        : `<span class="small muted">None triggered.</span>`;

      const ab = g("alertbox");
      if (r.alert) {
        ab.classList.remove("hidden");
        ab.className = "banner error";
        ab.innerHTML = `<b>Simulated alert (${esc(r.alert.channels.join(" + "))})</b> to
          ${esc(r.alert.to.phone)} / ${esc(r.alert.to.email)}<br />
          <span class="small">${esc(r.alert.message)}</span>`;
      } else ab.classList.add("hidden");
    }

    g("scenario").addEventListener("change", applyScenario);
    g("run").addEventListener("click", run);
    g("reset").addEventListener("click", () => { g("scenario").value = ""; });
    load();
  

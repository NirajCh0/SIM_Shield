/* metrics.page.js — extracted from metrics.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const kpi = (num, lbl) => `<div class="card kpi"><div class="num">${num}</div><div class="lbl">${lbl}</div></div>`;

    async function load() {
      initNav("metrics");
      let rep;
      try { rep = await getJSON("/api/evaluation"); }
      catch (_) { el("#noreport").classList.remove("hidden"); return; }

      // A fresh clone has no report yet — it is generated output and is
      // git-ignored. The endpoint now says so explicitly instead of 404ing,
      // so show the reason and the command rather than an empty page.
      if (rep.available === false) {
        const box = el("#noreport");
        box.textContent = `${rep.message} ${rep.how_to_fix || ""}`.trim();
        box.classList.remove("hidden");
        return;
      }

      // 1 · detection
      const d = rep.detection;
      if (d && d.available) {
        el("#det-kpis").innerHTML =
          kpi((d.accuracy*100).toFixed(1)+"%", "Accuracy") +
          kpi((d.recall_fraud*100).toFixed(1)+"%", "Recall (fraud caught)") +
          kpi(d.roc_auc.toFixed(3), "ROC-AUC") +
          kpi((d.precision_fraud*100).toFixed(1)+"%", "Precision (fraud)") +
          kpi((d.f1_fraud*100).toFixed(1)+"%", "F1 (fraud)") +
          kpi(d.n_test.toLocaleString(), "Test records");
        const m = d.confusion_matrix;
        el("#cm").innerHTML = `<table><tr><th></th><th>Pred legit</th><th>Pred fraud</th></tr>
          <tr><th>Actual legit</th><td>${m[0][0]}</td><td>${m[0][1]}</td></tr>
          <tr><th>Actual fraud</th><td>${m[1][0]}</td><td>${m[1][1]}</td></tr></table>`;
      } else {
        el("#det-kpis").innerHTML = kpi("—", "Train the model first (train_model.py)");
        el("#cm-card").classList.add("hidden");
      }

      // 2 · scenarios
      el("#scen").querySelector("tbody").innerHTML = rep.scenarios.cases.map((c) => `
        <tr><td>${esc(c.name)}</td><td>${c.expected}</td>
        <td><span class="decision d-${c.got}" style="font-size:12px;padding:3px 8px">${c.got}</span></td>
        <td>${c.risk_score}</td>
        <td style="color:${c.match ? "var(--ok)" : "var(--danger)"}">
          ${c.match ? icon("check", 17) : icon("x", 17)}</td></tr>`).join("");

      // 3 · user study
      const s = rep.user_study;
      el("#study-kpis").innerHTML =
        kpi(s.n, "Participants") +
        kpi(s.sus_mean != null ? s.sus_mean : "—", "Mean SUS" + (s.sus_grade ? " · " + s.sus_grade : "")) +
        kpi((s.knowledge_gain_mean != null ? (s.knowledge_gain_mean>0?"+":"") + s.knowledge_gain_mean : "—"), "Mean knowledge gain");
      const pre = s.pre_quiz_mean ?? 0, post = s.post_quiz_mean ?? 0, max = s.quiz_max || 5;
      el("#gainbars").innerHTML = [["Pre-quiz", pre], ["Post-quiz", post]].map(([l, v]) => `
        <div class="bar"><div class="lbl"><span>${l}</span><span>${v ?? "—"} / ${max}</span></div>
        <div class="track"><span style="width:${(v/max*100)||0}%"></span></div></div>`).join("");
      el("#studynote").textContent = s.n === 0
        ? "No submissions yet — take the study, then run evaluate.py."
        : `Confidence shifted ${s.confidence_before_mean} → ${s.confidence_after_mean} (1–5).`;
      el("#feedback").innerHTML = (s.feedback && s.feedback.length)
        ? s.feedback.map((f) => `<li>“${esc(f)}”</li>`).join("")
        : `<li class="muted">No free-text feedback yet.</li>`;

      // accountability
      try {
        const a = await getJSON("/api/audit/verify");
        el("#audit").innerHTML = icon(a.intact ? "lock" : "alert", 16) + " " +
          esc(a.message) + ` <span class="muted">(${a.entries} audit entries)</span>`;
      } catch (_) { el("#audit").textContent = "Audit log unavailable."; }
    }
    load();
    window.addEventListener('load', () => hydrateIcons());
  

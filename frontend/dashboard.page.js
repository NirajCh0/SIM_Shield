/* dashboard.page.js — extracted from dashboard.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const g = (id) => el("#" + id);
    const NPR = (v) => "NPR " + Number(v).toLocaleString("en-IN", { maximumFractionDigits: 0 });

    renderShell("dashboard", "Dashboard", {
      links: [{ href: "/money", label: "Exposure" }, { href: "/defence", label: "Defence" },
              { href: "/awareness", label: "Awareness" }],
    });

    function ring(score) {
      const deg = Math.round((score / 100) * 360);
      const col = score < 20 ? "#34c759" : score < 45 ? "#ffcc00" : score < 70 ? "#ff9500" : "#ff3b30";
      const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
      if (reduce) {
        g("ring").style.background = `conic-gradient(${col} ${deg}deg, var(--divider-soft) ${deg}deg)`;
        g("risk-num").textContent = score; return;
      }
      let cur = 0;
      const t0 = performance.now();
      (function step(t) {
        const p = Math.min(1, (t - t0) / 800);
        cur = (1 - Math.pow(1 - p, 3)) * deg;
        g("ring").style.background = `conic-gradient(${col} ${cur}deg, var(--divider-soft) ${cur}deg)`;
        if (p < 1) requestAnimationFrame(step);
      })(t0);
      countUp(g("risk-num"), score, { duration: 800 });
    }

    function sparkline(history, current) {
      const pts = history.map((h) => h.score).concat([current]).slice(-20);
      if (pts.length < 2) { g("spark").innerHTML = ""; return; }
      const w = 240, h = 34, pad = 3;
      const step = (w - pad * 2) / (pts.length - 1);
      const y = (v) => h - pad - (v / 100) * (h - pad * 2);
      const line = pts.map((v, i) => `${(pad + i * step).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
      const last = pts[pts.length - 1];
      const col = last < 20 ? "#34c759" : last < 45 ? "#ffcc00" : last < 70 ? "#ff9500" : "#ff3b30";
      g("spark").innerHTML =
        `<polyline points="${line}" fill="none" stroke="${col}" stroke-width="2"
           stroke-linejoin="round" stroke-linecap="round"/>
         <circle cx="${(pad + (pts.length - 1) * step).toFixed(1)}" cy="${y(last).toFixed(1)}"
           r="3" fill="${col}"/>`;
    }

    const sev = (s) => `<span class="sev sev-${esc(s)}">${esc(s)}</span>`;

    async function load() {
      let d;
      try { d = await getJSON("/api/me/dashboard"); }
      catch (_) { g("need-login").classList.remove("hidden"); bootPage(); return; }
      const u = d.user;
      g("main").style.display = "";
      g("greeting").textContent = `Namaste, ${u.display_name.split(" ")[0]}.`;
      const open = d.alerts.filter((a) => a.status === "new" || a.status === "escalated");
      g("subline").textContent = u.frozen
        ? "Your account is frozen — transactions are paused."
        : open.length ? `${open.length} thing${open.length > 1 ? "s" : ""} need your attention.`
                      : "Everything looks normal right now.";
      g("frozen-chip").innerHTML = u.frozen ? `<span class="decision d-FROZEN">FROZEN</span>` : "";

      ring(d.risk.score);
      g("risk-level").textContent = d.risk.level;
      g("risk-level").className = "decision d-" + d.risk.level;
      g("risk-reasons").innerHTML = d.risk.reasons.map((r) => `<li>${esc(r)}</li>`).join("");
      sparkline(d.risk_history || [], d.risk.score);

      const held = d.transactions.filter((t) => t.status === "held");
      g("verdict-actions").innerHTML = [
        held.length ? `<a class="btn small" href="/money">Release ${held.length} held payment${held.length > 1 ? "s" : ""}</a>` : "",
        open.length ? `<a class="btn ghost small" href="#alerts-jump">Review alerts</a>` : "",
        !u.frozen && d.risk.score >= 45 ? `<a class="btn ghost small" href="/defence">Freeze account</a>` : "",
      ].filter(Boolean).join("");

      // stats
      const statDefs = [
        ["wallet", "Available balance", NPR(u.balance),
         held.length ? `${NPR(held.reduce((s, t) => s + t.amount, 0))} on hold` : "no funds on hold"],
        ["bell", "Open alerts", String(open.length), open.length ? "review below" : "all clear"],
        ["sim", "SIM events (30d)", String(d.sim_events.length),
         d.sim_events.length ? "check they were you" : "no changes seen"],
        ["trophy", "Awareness points", String(u.points),
         u.badges.length ? `${u.badges.length} badge${u.badges.length > 1 ? "s" : ""} earned` : "earn your first badge"],
      ];
      g("stats").innerHTML = statDefs.map(([ic, label, val, sub]) => `
        <div class="stat reveal">
          <span class="stat-top">${icon(ic, 16)} ${esc(label)}</span>
          <span class="stat-val">${esc(val)}</span>
          <span class="stat-sub">${esc(sub)}</span>
        </div>`).join("");

      // quick actions
      const qa = [
        ["sim", "/money", "Exposure", "what a SIM swap would cost you"],
        [u.frozen ? "lock" : "snowflake", "/defence", u.frozen ? "Unfreeze account" : "Freeze account",
         u.frozen ? "needs an emailed code" : "pauses every transaction", !u.frozen],
        ["chat", "/assistant", "Ask the assistant", "explains your alerts"],
        ["book", "/awareness", "Learn & practise", "spot-the-scam trainer"],
      ];
      g("quick").innerHTML = qa.map(([ic, href, label, sub, danger]) => `
        <a class="qa reveal${danger ? " danger" : ""}" href="${href}">
          ${icon(ic, 22)}<span>${esc(label)}</span>
          <span class="qa-sub">${esc(sub)}</span></a>`).join("");

      // alerts
      g("alert-count").textContent = `${open.length} open`;
      g("alert-list").innerHTML = d.alerts.length ? d.alerts.slice(0, 6).map((a) => `
        <div class="item">
          <div class="grow">
            <div class="title">${sev(a.severity)} ${esc(a.alert_type.replace(/_/g, " "))}
              <span class="status-chip">${esc(a.status)}</span></div>
            <div class="desc">${esc(a.message)}</div>
          </div>
          <div style="text-align:right">
            <div class="when">${fmtWhen(a.created_at)}</div>
            ${a.status === "new" ? `<button class="subtle small" data-ack="${a.id}">Reviewed</button>` : ""}
          </div>
        </div>`).join("")
        : `<div class="empty">${icon("check", 30)}<p>No alerts — all quiet.</p></div>`;
      g("alert-list").querySelectorAll("[data-ack]").forEach((b) =>
        b.addEventListener("click", async () => {
          await postJSON(`/api/me/alerts/${b.dataset.ack}/ack`, {}); load();
        }));

      g("activity-list").innerHTML = d.activity.length ? d.activity.slice(0, 12).map((a) => `
        <div class="item"><div class="grow"><div class="desc">${esc(a.action.replace(/_/g, " "))}</div></div>
        <div class="when">${fmtWhen(a.created_at)}</div></div>`).join("")
        : `<div class="empty">${icon("clock", 30)}<p>No activity yet.</p></div>`;

      bootPage();
    }

    g("btn-simswap").addEventListener("click", async () => {
      const b = g("btn-simswap");
      b.disabled = true; b.textContent = "Running…";
      await postJSON("/api/me/simulate-sim-swap", {});
      b.disabled = false; b.textContent = "Run simulation";
      load();
    });

    load();
  

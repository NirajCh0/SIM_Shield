/* money.page.js — the Exposure page.
 *
 * SCOPE NOTE. This page used to be a small banking app: a savings-account
 * number, a merchant field, quick-spend presets, "Send money", a transfer
 * history and an explainer of the four transaction-scoring rules. That framing
 * invited the reader to evaluate SIMShield as banking software, which it is
 * not and does not claim to be.
 *
 * What survives is the part that is genuinely a SIM-swap countermeasure: the
 * cooling-off hold applied after a SIM change, released only by an out-of-band
 * code. The amount field remains because the hold needs something to act on,
 * not because sending money is a feature.
 *
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const g = (id) => el("#" + id);
    const NPR = (v) => "NPR " + Number(v).toLocaleString("en-IN", { maximumFractionDigits: 0 });
    let USER = null, pendingRelease = null;

    renderShell("money", "Exposure", {
      links: [{ href: "/dashboard", label: "Dashboard" }, { href: "/defence", label: "Defence" }],
    });

    async function load() {
      let d;
      try { d = await getJSON("/api/me/dashboard"); }
      catch (_) { g("need-login").classList.remove("hidden"); bootPage(); return; }
      USER = d.user;
      g("main").style.display = "";

      countUp(g("balance"), USER.balance, { format: (v) => NPR(v) });

      const held = d.transactions.filter((t) => t.status === "held");
      g("held-note").textContent = held.length
        ? `${NPR(held.reduce((s, t) => s + t.amount, 0))} held pending your release code`
        : "Nothing on hold.";
      g("frozen-banner").innerHTML = USER.frozen
        ? `<div class="banner error" style="margin:0">${icon("snowflake", 16)} <b>Account frozen.</b>
             Payments are refused until you unfreeze from <a href="/defence">Defence</a>.</div>` : "";

      g("held-section").classList.toggle("hidden", held.length === 0);
      g("held-list").innerHTML = held.map((t) => `
        <div class="item">
          <div class="grow">
            <div class="title">${NPR(t.amount)}</div>
            <div class="desc muted">${esc((t.reasons || [])[0] || "")}</div>
          </div>
          <button class="small" data-release="${t.id}" data-amt="${t.amount}">Release…</button>
        </div>`).join("");
      bindRelease(g("held-list"));

      renderAttempts(d.transactions);
      bootPage();
    }

    function bindRelease(root) {
      root.querySelectorAll("[data-release]").forEach((b) =>
        b.addEventListener("click", () => openRelease(b.dataset.release, b.dataset.amt)));
    }

    function renderAttempts(list) {
      g("txn-rows").innerHTML = list.length ? list.map((t) => {
        const badge = t.status === "held" ? `<span class="sev sev-warning">held</span>`
          : t.flagged ? `<span class="sev sev-critical">flagged</span>`
          : `<span class="status-chip">${esc(t.status || "allowed")}</span>`;
        return `<tr>
          <td>${fmtWhen(t.occurred_at)}</td>
          <td style="font-variant-numeric:tabular-nums">${NPR(t.amount)}</td>
          <td>${t.anomaly_score ?? 0}</td>
          <td>${badge}</td>
          <td>${t.status === "held"
                ? `<button class="subtle small" data-release="${t.id}"
                     data-amt="${t.amount}">Release</button>` : ""}</td>
        </tr>`;
      }).join("") : `<tr><td colspan="5"><div class="empty">${icon("clock", 28)}
        <p>No payment attempts yet. Try one above.</p></div></td></tr>`;
      bindRelease(g("txn-rows"));
    }

    g("btn-txn").addEventListener("click", async () => {
      const amt = parseFloat(g("txn-amount").value);
      if (!(amt > 0)) { showResult("error", "Enter an amount greater than zero."); return; }
      const btn = g("btn-txn"); btn.disabled = true;
      // No merchant is sent: SIMShield has no reason to record what a subscriber
      // buys, and the cooling-off rule does not use it.
      const { ok, status, data } = await postJSON("/api/me/transactions", { amount: amt });
      btn.disabled = false;
      if (!ok && status !== 403) { showResult("error", data.error || "Failed."); return; }
      const kind = data.status === "held" ? "" : (data.flagged || data.accepted === false) ? "error" : "okay";
      const lead = data.accepted === false ? "Refused." :
                   data.status === "held" ? "Held for your protection." :
                   data.flagged ? "Allowed, but flagged." : "Allowed.";
      showResult(kind, `<b>${lead}</b> Risk ${data.anomaly_score}/100 — ${esc((data.reasons || []).join(" "))}`);
      g("txn-amount").value = "";
      load();
    });

    function showResult(kind, html) {
      const box = g("txn-result");
      box.className = "banner " + kind;
      box.innerHTML = html;
      box.classList.remove("hidden");
    }

    /* --- release flow: the out-of-band step the whole hold exists for -------- */
    async function openRelease(id, amt) {
      pendingRelease = id;
      g("release-desc").textContent =
        `${NPR(amt)} — we'll email you a one-time code to authorise it. Email, not SMS: ` +
        `whoever holds your number cannot read it.`;
      g("release-err").classList.add("hidden");
      g("release-code").value = "";
      g("release-modal").classList.remove("hidden");
      const { ok, data } = await postJSON(`/api/me/transactions/${id}/release/request`, {});
      const code = ok && data.delivery && data.delivery.demo && data.delivery.demo.otp;
      if (code) {
        g("release-demo-otp").innerHTML =
          `Demo outbox — your release code is <span class="mono" style="font-size:16px">${esc(code)}</span>`;
        g("release-demo-otp").classList.remove("hidden");
      }
      g("release-code").focus();
    }

    g("btn-release-cancel").addEventListener("click", () =>
      g("release-modal").classList.add("hidden"));

    g("btn-release-confirm").addEventListener("click", async () => {
      const { ok, data } = await postJSON(`/api/me/transactions/${pendingRelease}/release/confirm`,
        { code: g("release-code").value.trim() });
      if (!ok) {
        g("release-err").textContent = data.error || "Failed.";
        g("release-err").classList.remove("hidden");
        return;
      }
      g("release-modal").classList.add("hidden");
      load();
    });

    /* Show the configured lookback window rather than hardcoding a number in
       the copy, so the page cannot drift from config.yaml. */
    getJSON("/api/config/public").then((c) => {
      const days = c && c.sim_change_lookback_days;
      if (days) g("lookback-days").textContent = days;
    }).catch(() => {});

    load();

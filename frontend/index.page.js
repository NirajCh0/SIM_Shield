/* index.page.js — extracted from index.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    renderShell("home", "SIMShield", {
      tabs: false,
      links: [{ href: "#attack", label: "The attack" }, { href: "#how", label: "How it works" },
              { href: "/detection", label: "Detection demo" }],
      cta: { href: "/register", label: "Get started" },
    });
    bootPage();

    (async () => {
      try {
        const e = await getJSON("/api/education");
        el("#signs").innerHTML = e.warning_signs.map((x) => `<li>${esc(x)}</li>`).join("");
      } catch (_) {}
      try {
        const et = await getJSON("/api/ethics");
        el("#ethics-banner").innerHTML = `<b>Scope</b> — ${esc(et.scope)}`;
      } catch (_) { el("#ethics-banner").classList.add("hidden"); }

      // live status strip — real numbers from the running system
      let mode = "rules-only", ml = false;
      try { const h = await getJSON("/api/health"); ml = h.ml_model_loaded; mode = h.mode; } catch (_) {}
      const tiles = [
        ["shieldCheck", ml ? "4" : "2", "signals fused per login", "rules · behaviour · RF · IsoForest"],
        ["chart", "100k", "records trained on", "synthetic telecom dataset"],
        ["clock", "pre-OTP", "when scoring happens", "before any code is sent"],
        ["chat", "EN · ने", "assistant languages", "explains your own alerts"],
      ];
      el("#status-strip").innerHTML = tiles.map(([ic, val, label, sub]) => `
        <div class="stat reveal">
          <span class="stat-top">${icon(ic, 16)} ${esc(label)}</span>
          <span class="stat-val">${esc(val)}</span>
          <span class="stat-sub">${esc(sub)}</span>
        </div>`).join("");
      renderFeatures();
      initReveal();
    })();

    /* --- editorial feature cards + chip filter ------------------------------ */
    const FEATURES = [
      { cat: "Sign-in", art: "gate", kicker: "Two-step sign-in",
        title: "The code is never sent to a hijacked phone",
        sub: "Password, then an emailed code — and the risk check runs before that code exists." },
      { cat: "Containment", art: "vault", kicker: "One-tap freeze",
        title: "Pause everything the moment you suspect trouble",
        sub: "Unfreezing needs an emailed code, so a stolen password alone isn't enough." },
      { cat: "Containment", art: "alert", kicker: "Cooling-off holds",
        title: "Big transfers wait after a SIM change",
        sub: "Held until you release them out-of-band, on a channel the attacker doesn't hold." },
      { cat: "Awareness", art: "signal", kicker: "Know the moment",
        title: "Sudden loss of signal is the one sign you can see",
        sub: "We teach the symptom, and the first ten minutes that matter most." },
      { cat: "Sign-in", art: "simcard", kicker: "SIM intelligence",
        title: "A SIM activated days ago is the loudest signal there is",
        sub: "Recency, IMSI and ICCID changes and swap history are weighted above location." },
      { cat: "Awareness", art: "theft", kicker: "Bilingual assistant",
        title: "Your alerts, explained in plain English or नेपाली",
        sub: "It walks you through recovery and escalates to a human fraud team." },
    ];

    function renderFeatures(filter = "All") {
      const cats = ["All", ...new Set(FEATURES.map((f) => f.cat))];
      el("#feature-chips").innerHTML = cats.map((c) =>
        `<button class="chip${c === filter ? " active" : ""}" data-cat="${esc(c)}">${esc(c)}</button>`).join("");
      el("#feature-chips").querySelectorAll("[data-cat]").forEach((b) =>
        b.addEventListener("click", () => renderFeatures(b.dataset.cat)));

      const shown = FEATURES.filter((f) => filter === "All" || f.cat === filter);
      el("#feature-grid").innerHTML = shown.map((f) => `
        <a class="ed-card reveal" href="/register">
          <div class="ed-art">${art(f.art)}</div>
          <div class="ed-body">
            <div class="ed-kicker">${esc(f.kicker)}</div>
            <div class="ed-title">${esc(f.title)}</div>
            <div class="ed-sub">${esc(f.sub)}</div>
          </div>
        </a>`).join("");
      initReveal();
    }
  

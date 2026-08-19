/* awareness.page.js — extracted from awareness.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const g = (id) => el("#" + id);
    let lang = localStorage.getItem("simshield_lang") || "en";
    let USER = null;

    renderShell("awareness", "Awareness", {
      links: [{ href: "/assistant", label: "Assistant" }, { href: "/study", label: "User study" }],
    });

    const CHECKLIST = [
      ["sim_pin", "I set a SIM PIN on my phone"],
      ["operator_pin", "I set an account PIN with my operator"],
      ["auth_app", "I use an authenticator app where my bank supports it"],
      ["alerts_on", "I turned on login and transaction alerts"],
      ["hotline_saved", "I saved my bank and operator hotlines"],
    ];

    async function loadEducation() {
      const e = await getJSON("/api/education");
      g("what").textContent = e.what_is_sim_swap;
      const fill = (id, arr) => g(id).innerHTML = arr.map((x) => `<li>${esc(x)}</li>`).join("");
      fill("signs", e.warning_signs);
      fill("protect", e.protect_yourself);
      fill("attacked", e.if_attacked);
    }

    async function loadPlaybook() {
      const pb = await getJSON("/api/playbook?lang=" + lang);
      g("pb-list").innerHTML = pb.phases.map((p, i) => `
        <details class="accordion"${i === 0 ? " open" : ""}>
          <summary>${esc(p.name)}</summary>
          <ol class="small" style="color:var(--ink-80);padding-left:20px;line-height:1.8">
            ${p.steps.map((s) => `<li style="margin:6px 0">${esc(s)}</li>`).join("")}
          </ol></details>`).join("");
      g("lang-toggle").textContent = lang === "en" ? "नेपालीमा" : "In English";
    }

    g("lang-toggle").addEventListener("click", () => {
      lang = lang === "en" ? "ne" : "en";
      localStorage.setItem("simshield_lang", lang);
      loadPlaybook();
    });

    async function loadProgress() {
      let d;
      try { d = await getJSON("/api/me/dashboard"); } catch (_) { return; }
      USER = d.user;
      g("progress-card").classList.remove("hidden");
      g("points-chip").textContent = `${USER.points} points`;
      g("badge-row").innerHTML = d.badge_catalog.map((b) => `
        <span class="badge ${USER.badges.includes(b.id) ? "" : "locked"}"
              title="${esc(b.label)} — needs ${b.min_points} points">
          ${icon("trophy", 15)} ${esc(b.label)}</span>`).join("");
      g("checklist").innerHTML = CHECKLIST.map(([id, label]) => `
        <label class="check-row" style="margin:10px 0;font-weight:400">
          <input type="checkbox" data-check="${id}" /> ${esc(label)}</label>`).join("");
      g("checklist").querySelectorAll("[data-check]").forEach((c) =>
        c.addEventListener("change", async () => {
          if (!c.checked) return;
          c.disabled = true;
          const { data } = await postJSON("/api/me/checklist", { item: c.dataset.check });
          if (data.awarded) {
            USER.points = data.total;
            g("points-chip").textContent = `${data.total} points`;
          }
        }));
    }

    /* --- spot the scam ------------------------------------------------------- */
    let SCAM = [], idx = 0, right = 0;
    async function round() {
      SCAM = await getJSON("/api/scamsim/quiz?n=5");
      idx = 0; right = 0;
      g("scam-box").classList.remove("hidden");
      g("scam-done").classList.add("hidden");
      show();
    }
    function show() {
      g("scam-msg").textContent = SCAM[idx].text;
      g("scam-progress").textContent = `${idx + 1} of ${SCAM.length} · ${right} correct`;
      g("scam-verdict").classList.add("hidden");
      g("scam-next").classList.add("hidden");
      g("scam-yes").disabled = g("scam-no").disabled = false;
    }
    async function guess(isScam) {
      g("scam-yes").disabled = g("scam-no").disabled = true;
      const { data } = await postJSON("/api/scamsim/check",
        { id: SCAM[idx].id, guess_scam: isScam });
      if (data.correct) right++;
      const v = g("scam-verdict");
      v.className = "banner " + (data.correct ? "okay" : "error");
      v.innerHTML = `<b>${data.correct ? "Correct" : "Not quite"}</b> — this is
        <b>${data.is_scam ? "a scam" : "legitimate"}</b>. ${esc(data.explain)}` +
        (data.points ? ` <b>+${data.points} points</b>` : "");
      v.classList.remove("hidden");
      g("scam-next").classList.remove("hidden");
      g("scam-progress").textContent = `${idx + 1} of ${SCAM.length} · ${right} correct`;
    }
    g("scam-yes").addEventListener("click", () => guess(true));
    g("scam-no").addEventListener("click", () => guess(false));
    g("scam-next").addEventListener("click", () => {
      idx++;
      if (idx >= SCAM.length) {
        g("scam-box").classList.add("hidden");
        g("scam-done").classList.remove("hidden");
        g("scam-score").innerHTML = `<b>Round complete: ${right} of ${SCAM.length} correct.</b> ` +
          (right === SCAM.length ? "You're hard to fool."
            : "Read the explanations above, then try another round.");
      } else show();
    });
    g("scam-restart").addEventListener("click", round);

    (async () => {
      await loadEducation();
      await loadPlaybook();
      await loadProgress();
      await round();
      bootPage();
    })();
  

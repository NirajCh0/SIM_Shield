/* study.page.js — extracted from study.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    let INSTR = null;
    const g = (id) => el("#" + id);
    const show = (id) => { g(id).scrollIntoView({ behavior: "smooth" }); };

    function quizHTML(prefix) {
      return INSTR.quiz.map((q) => `
        <div style="margin:12px 0">
          <div><b>${esc(q.prompt)}</b></div>
          ${q.options.map((o, i) => `<label style="display:flex;gap:8px;align-items:center;color:var(--ink)">
            <input type="radio" name="${prefix}_${q.id}" value="${i}" style="width:auto"> ${esc(o)}</label>`).join("")}
        </div>`).join("");
    }
    function readQuiz(prefix) {
      const ans = {};
      INSTR.quiz.forEach((q) => {
        const sel = document.querySelector(`input[name="${prefix}_${q.id}"]:checked`);
        if (sel) ans[q.id] = parseInt(sel.value);
      });
      return ans;
    }

    async function load() {
      initNav("study");
      INSTR = await getJSON("/api/study/instrument");
      const et = await getJSON("/api/ethics");
      g("ethics").innerHTML = icon("info", 16) + " " + esc(et.scope);
      g("cver").textContent = INSTR.consent_version;
      g("purposes").innerHTML = INSTR.purposes.map((p) => `<li>${esc(p)}</li>`).join("");
      g("preq").innerHTML = quizHTML("pre");
      g("postq").innerHTML = quizHTML("post");
      g("sus").innerHTML = INSTR.sus_items.map((s, i) => `
        <div class="flag"><span>${i + 1}. ${esc(s)}</span>
        <select id="sus_${i}" style="width:70px">${[1,2,3,4,5].map((n)=>`<option>${n}</option>`).join("")}</select></div>`).join("");

      const edu = await getJSON("/api/education");
      g("learn").innerHTML = `<p class="muted">${esc(edu.what_is_sim_swap)}</p>
        <h3>Warning signs</h3><ul class="clean">${edu.warning_signs.map((x)=>`<li>${esc(x)}</li>`).join("")}</ul>
        <h3>Protect yourself</h3><ul class="clean">${edu.protect_yourself.map((x)=>`<li>${esc(x)}</li>`).join("")}</ul>`;
    }

    let preAns = {};
    g("agree").addEventListener("change", (e) => g("toPre").disabled = !e.target.checked);
    g("toPre").addEventListener("click", () => { g("s-consent").classList.add("hidden"); g("s-pre").classList.remove("hidden"); show("s-pre"); });
    g("toLearn").addEventListener("click", () => { preAns = readQuiz("pre"); g("s-pre").classList.add("hidden"); g("s-learn").classList.remove("hidden"); show("s-learn"); });
    g("toPost").addEventListener("click", () => { g("s-learn").classList.add("hidden"); g("s-post").classList.remove("hidden"); show("s-post"); });

    g("submit").addEventListener("click", async () => {
      const sus = INSTR.sus_items.map((_, i) => parseInt(g("sus_" + i).value));
      const payload = {
        consent: { agreed: true, version: INSTR.consent_version },
        pre_quiz: preAns, post_quiz: readQuiz("post"), sus,
        confidence_before: parseInt(g("cb").value), confidence_after: parseInt(g("ca").value),
        feedback: g("feedback").value,
      };
      const { ok, data } = await postJSON("/api/study/submit", payload);
      if (!ok) { alert(data.error || "Submit failed"); return; }
      // gamification: signed-in participants earn awareness points
      if (getToken()) {
        postJSON("/api/me/gamify/study_completed", {});
        if (data.summary.post_score === INSTR.quiz.length)
          postJSON("/api/me/gamify/quiz_perfect", {});
      }
      g("s-post").classList.add("hidden"); g("s-done").classList.remove("hidden"); show("s-done");
      g("thanks").textContent = `Recorded as ${data.participant_id}. Knowledge gain: ` +
        `${data.summary.knowledge_gain > 0 ? "+" : ""}${data.summary.knowledge_gain} of ${INSTR.quiz.length}` +
        (data.summary.sus_score != null ? ` · your SUS usability score: ${data.summary.sus_score}/100.` : ".");
    });

    load();
    window.addEventListener('load', () => hydrateIcons());
  

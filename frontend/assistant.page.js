/* assistant.page.js — extracted from assistant.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const g = (id) => el("#" + id);
    let lang = localStorage.getItem("simshield_chat_lang") || "en";
    let busy = false;

    renderShell("assistant", "Assistant", {
      links: [{ href: "/awareness", label: "Awareness" }, { href: "/dashboard", label: "Dashboard" }],
    });

    const SUGGEST = {
      en: ["What is a SIM swap?", "Warning signs", "How do I protect myself?",
           "Explain my alert", "Recovery steps", "Is it safe to share an OTP?",
           "Useful contacts", "Talk to the fraud team"],
      ne: ["SIM swap के हो?", "खतराका संकेत", "कसरी सुरक्षित रहने?",
           "मेरो अलर्ट बुझाऊ", "रिकभरी चरणहरू", "OTP साझा गर्न हुन्छ?",
           "सम्पर्क नम्बरहरू", "Fraud team सँग कुरा"],
    };
    const GREET = {
      en: "Namaste. Ask me anything about SIM-swap fraud, or tap a suggestion below.",
      ne: "नमस्ते। SIM-swap सम्बन्धी जे पनि सोध्नुहोस्, वा तलको सुझाव थिच्नुहोस्।",
    };

    function bubble(text, who, opts = {}) {
      const row = document.createElement("div");
      row.className = "msg-row " + who;
      row.innerHTML = `<div class="msg ${who}">${esc(text)}</div>`;
      g("log").appendChild(row);
      g("log").scrollTop = g("log").scrollHeight;
      return row;
    }

    function typing() {
      const row = document.createElement("div");
      row.className = "msg-row bot";
      row.innerHTML = `<div class="msg bot typing"><span></span><span></span><span></span></div>`;
      g("log").appendChild(row);
      g("log").scrollTop = g("log").scrollHeight;
      return row;
    }

    function renderSuggest() {
      g("suggest").innerHTML = SUGGEST[lang]
        .map((s) => `<button type="button">${esc(s)}</button>`).join("");
      g("suggest").querySelectorAll("button").forEach((b) =>
        b.addEventListener("click", () => send(b.textContent)));
      g("lang-toggle").textContent = lang === "en" ? "नेपालीमा" : "In English";
      g("input").placeholder = lang === "en" ? "Type your question…" : "आफ्नो प्रश्न लेख्नुहोस्…";
    }

    async function send(text) {
      const msg = (text ?? g("input").value).trim();
      if (!msg || busy) return;
      busy = true;
      g("input").value = "";
      bubble(msg, "user");
      const t = typing();
      try {
        const { ok, data } = await postJSON("/api/chat", { message: msg, lang });
        t.remove();
        if (!ok) { bubble(data.error || "Something went wrong.", "bot"); busy = false; return; }
        if (data.lang && data.lang !== lang) {
          lang = data.lang;
          localStorage.setItem("simshield_chat_lang", lang);
          renderSuggest();
        }
        bubble(data.reply, "bot");
        if (data.escalated) {
          const n = document.createElement("div");
          n.className = "banner error";
          n.style.margin = "8px 0";
          n.innerHTML = `${icon("users", 16)} <b>Escalated.</b> A human on the fraud team will
            review your account.`;
          g("log").appendChild(n);
          g("log").scrollTop = g("log").scrollHeight;
        }
      } catch (_) {
        t.remove();
        bubble("I can't reach the server — check your connection and try again.", "bot");
      }
      busy = false;
    }

    g("compose").addEventListener("submit", (e) => { e.preventDefault(); send(); });
    g("lang-toggle").addEventListener("click", () => {
      lang = lang === "en" ? "ne" : "en";
      localStorage.setItem("simshield_chat_lang", lang);
      renderSuggest();
      bubble(GREET[lang], "bot");
    });

    (async () => {
      renderSuggest();
      const u = await currentUser();
      if (u) g("tagline").textContent =
        `Signed in as ${u.display_name.split(" ")[0]} — I can explain your own alerts and escalate to the fraud team.`;
      bubble(GREET[lang], "bot");
      // replay recent history for signed-in users so the thread feels continuous
      if (u) {
        try {
          const hist = await getJSON("/api/chat/history");
          hist.slice(-6).forEach((h) => { bubble(h.query, "user"); bubble(h.response, "bot"); });
        } catch (_) {}
      }
      bootPage();
    })();
  

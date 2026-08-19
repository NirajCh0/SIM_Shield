/* register.page.js — extracted from register.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const g = (id) => el("#" + id);

    async function loadProfiles() {
      try {
        const users = await getJSON("/api/users");
        // { synthetic: true, profiles: [...] } — see detection.page.js.
        const profiles = users.profiles || users;
        g("profile").innerHTML = `<option value="">— none —</option>` + profiles.map((u) =>
          `<option value="${esc(u.user_id)}">${esc(u.display_name)} (${esc(u.operator)}, SIM since ${esc(u.sim_activation_date)})</option>`
        ).join("");
      } catch (_) {}
    }

    /* password strength meter (client-side hint; server enforces min length) */
    g("password").addEventListener("input", () => {
      const p = g("password").value;
      let s = 0;
      if (p.length >= 8) s++;
      if (p.length >= 12) s++;
      if (/[A-Z]/.test(p) && /[a-z]/.test(p)) s++;
      if (/\d/.test(p)) s++;
      if (/[^A-Za-z0-9]/.test(p)) s++;
      const pct = [0, 20, 40, 60, 80, 100][s];
      const col = s <= 1 ? "#ff3b30" : s <= 3 ? "#ff9500" : "#34c759";
      g("strength-bar").style.width = pct + "%";
      g("strength-bar").style.background = col;
      g("strength-note").textContent = p ?
        ["Very weak", "Weak", "Fair", "Good", "Strong", "Excellent"][s] +
        " — use length, cases, digits and symbols." : "";
    });

    g("btn-register").addEventListener("click", async () => {
      g("err").classList.add("hidden");
      g("btn-register").disabled = true;
      const { ok, data } = await postJSON("/api/auth/register", {
        display_name: g("name").value.trim(),
        email: g("email").value.trim(),
        phone: g("phone").value.trim(),
        operator: g("operator").value,
        language: g("language").value,
        password: g("password").value,
        trusted_contact: g("trusted").value.trim(),
        profile_id: g("profile").value || null,
      });
      g("btn-register").disabled = false;
      if (!ok) {
        g("err").textContent = data.error || "Registration failed.";
        g("err").classList.remove("hidden");
        return;
      }
      g("form-card").classList.add("hidden");
      g("done-card").classList.remove("hidden");
    });

    initNav();
    loadProfiles();
    window.addEventListener('load', () => hydrateIcons());
  

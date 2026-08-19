/* login.page.js — extracted from login.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 */
    const g = (id) => el("#" + id);
    const show = (id, on = true) => g(id).classList.toggle("hidden", !on);
    const setErr = (id, msg) => { g(id).textContent = msg || ""; show(id, !!msg); };
    let pendingEmail = "";

    function swap(step) {
      ["step-password", "step-otp", "step-forgot"].forEach((s) => show(s, s === step));
    }

    function showDemoOtp(bannerId, delivery) {
      // demo mode only: the backend reveals the OTP when no SMTP is configured
      const code = delivery && delivery.demo && delivery.demo.otp;
      if (code) {
        g(bannerId).innerHTML = `${icon("send", 16)} <b>Demo outbox</b> — no real email is sent in demo ` +
          `mode. Your code is <span class="mono" style="font-size:16px">${esc(code)}</span>`;
        show(bannerId);
      } else { show(bannerId, false); }
    }

    /* Browser geolocation (optional, 2.5 s budget) — feeds the Haversine
       distance-from-safe-zone component of the pre-OTP risk check. */
    function getLocation() {
      return new Promise((resolve) => {
        if (!g("share-loc").checked || !navigator.geolocation) return resolve(null);
        const timer = setTimeout(() => resolve(null), 2500);
        navigator.geolocation.getCurrentPosition(
          (pos) => { clearTimeout(timer);
                     resolve({ lat: pos.coords.latitude, lon: pos.coords.longitude }); },
          () => { clearTimeout(timer); resolve(null); },
          { maximumAge: 300000, timeout: 2400 });
      });
    }

    // The server-issued login challenge binds the emailed code to this browser
    // and this attempt (SECURITY_REMEDIATION.md F7).
    let pendingChallenge = "";

    async function doLogin() {
      setErr("err1", "");
      g("btn-login").disabled = true;
      const location = await getLocation();
      const { ok, status, data } = await postJSON("/api/auth/login", {
        email: g("email").value.trim(), password: g("password").value,
        fingerprint: deviceFingerprint(), location,
      });
      pendingChallenge = data.challenge || "";
      g("btn-login").disabled = false;
      if (!ok) {
        setErr("err1", data.error || "Sign-in failed.");
        if (status === 403 && data.reasons) {
          setErr("err1", data.error + " Reasons: " + data.reasons.join(" "));
        }
        return;
      }
      pendingEmail = g("email").value.trim();
      // A session with 2FA disabled is already established by the Set-Cookie
      // on this response — there is no token in the body to look for.
      if (!data.otp_required && data.user) { finish(data); return; }
      swap("step-otp");
      showDemoOtp("demo-otp", data.delivery);
      const pre = data.pre_otp_check;
      if (pre) {
        g("risknote").textContent = `Pre-OTP risk check: ${pre.decision} ` +
          `(risk ${pre.risk_score}/100). ${pre.reasons[0]}`;
        g("risknote").className = "banner " +
          (pre.decision === "ALLOW" ? "okay" : (pre.decision === "MONITOR" ? "" : "error"));
        show("risknote");
      }
      g("otp").focus();
    }

    async function doVerify(codeOverride) {
      setErr("err2", "");
      const { ok, data } = await postJSON("/api/auth/verify-otp", {
        email: pendingEmail, code: codeOverride || g("otp").value.trim(),
        challenge: pendingChallenge,
        fingerprint: deviceFingerprint(), device_label: navigator.platform || "Web",
      });
      if (!ok) { setErr("err2", data.error || "Verification failed."); return; }
      finish(data);
    }

    function finish(data) {
      // Nothing to store. The session arrives as an HttpOnly cookie the browser
      // sends automatically, and the CSRF token as its own readable cookie that
      // script.js picks up. Keeping either in JS was what made an XSS able to
      // steal a session in the first place.
      location.href = data.user.role === "admin" ? "/admin" : "/dashboard";
    }

    g("btn-login").addEventListener("click", doLogin);
    g("password").addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); });
    g("btn-verify").addEventListener("click", () => doVerify());
    g("otp").addEventListener("keydown", (e) => { if (e.key === "Enter") doVerify(); });

    // Biometric step-up (demo). On a real mobile app this would be
    // WebAuthn / platform biometrics; here it fills the code from the demo
    // banner to illustrate the step-up UX.
    g("btn-bio").addEventListener("click", () => {
      const m = (g("demo-otp").textContent || "").match(/(\d{6})/);
      if (m) { g("otp").value = m[1]; doVerify(m[1]); }
      else setErr("err2", "Biometric demo needs the demo outbox code (demo mode only).");
    });

    g("link-resend").addEventListener("click", async (e) => {
      e.preventDefault();
      const { ok, data } = await postJSON("/api/auth/resend-otp", {
        email: pendingEmail, challenge: pendingChallenge,
        fingerprint: deviceFingerprint() });
      if (ok) showDemoOtp("demo-otp", data.delivery);
      else setErr("err2", data.error || "Could not resend.");
    });
    g("link-back").addEventListener("click", (e) => { e.preventDefault(); swap("step-password"); });
    g("link-forgot").addEventListener("click", (e) => { e.preventDefault(); swap("step-forgot"); });
    g("link-back2").addEventListener("click", (e) => { e.preventDefault(); swap("step-password"); });

    g("btn-forgot-send").addEventListener("click", async () => {
      setErr("err3", "");
      const { ok, data } = await postJSON("/api/auth/reset/request",
                                          { email: g("f-email").value.trim() });
      if (!ok) { setErr("err3", data.error || "Request failed."); return; }
      g("ok3").textContent = data.message; show("ok3"); show("forgot-2");
      showDemoOtp("demo-otp-f", data.delivery);
    });
    g("btn-forgot-confirm").addEventListener("click", async () => {
      setErr("err3", "");
      const { ok, data } = await postJSON("/api/auth/reset/confirm", {
        email: g("f-email").value.trim(), code: g("f-code").value.trim(),
        new_password: g("f-pass").value,
      });
      if (!ok) { setErr("err3", data.error || "Reset failed."); return; }
      g("ok3").textContent = data.message + " Redirecting…"; show("ok3");
      setTimeout(() => swap("step-password"), 1200);
    });

    initNav();
    window.addEventListener('load', () => hydrateIcons());
  

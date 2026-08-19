/* SIMShield PWA runtime: service-worker registration, install prompt,
 * push-notification opt-in, and the connectivity watcher.
 *
 * SCOPE HONESTY — read before citing this file.
 * The web platform cannot see SIM or cellular-radio state. `navigator.onLine`
 * reports whether the *browser* has a network route, and the Network
 * Information API (where supported) reports the active transport. Neither can
 * tell you a SIM was swapped: a hijacked SIM on a device still connected to
 * Wi-Fi produces no signal at all here.
 *
 * So the watcher below is deliberately framed as a PROMPT, not a detector: a
 * sustained loss of connectivity is a moment worth asking the user "do you
 * also have no mobile signal?", because sudden loss of service is the one
 * symptom a victim can observe. The authoritative detection stays server-side
 * (operator SIM-change feed + the pre-OTP risk engine). A native React Native /
 * Flutter client could read real cellular state and turn this prompt into an
 * actual detector — that is documented as future work.
 */
(function () {
  const OFFLINE_PROMPT_AFTER_MS = 20000; // sustained loss before we ask
  let offlineSince = null;
  let offlineTimer = null;
  let deferredInstall = null;

  /* --- service worker ----------------------------------------------------- */
  if ("serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("/sw.js").catch((e) =>
        console.warn("[pwa] service worker registration failed:", e));
    });
  }

  /* --- small toast/banner host -------------------------------------------- */
  function host() {
    let h = document.getElementById("pwa-host");
    if (!h) {
      h = document.createElement("div");
      h.id = "pwa-host";
      h.className = "pwa-host";
      document.body.appendChild(h);
    }
    return h;
  }

  function banner(id, html, kind) {
    let b = document.getElementById(id);
    if (b) return b;
    b = document.createElement("div");
    b.id = id;
    b.className = "pwa-banner " + (kind || "");
    b.innerHTML = html;
    host().appendChild(b);
    const close = b.querySelector("[data-dismiss]");
    if (close) close.addEventListener("click", () => b.remove());
    return b;
  }

  /* --- install prompt ------------------------------------------------------ */
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredInstall = e;
    if (localStorage.getItem("simshield_install_dismissed") === "1") return;
    const b = banner("pwa-install",
      `<span><b>Install SIMShield</b> — add it to your home screen for
       instant freeze and push alerts.</span>
       <span class="pwa-actions">
         <button class="small" id="pwa-install-go">Install</button>
         <button class="subtle small" data-dismiss>Not now</button>
       </span>`);
    b.querySelector("#pwa-install-go").addEventListener("click", async () => {
      b.remove();
      if (!deferredInstall) return;
      deferredInstall.prompt();
      await deferredInstall.userChoice.catch(() => {});
      deferredInstall = null;
    });
    b.querySelector("[data-dismiss]").addEventListener("click", () =>
      localStorage.setItem("simshield_install_dismissed", "1"));
  });

  /* --- connectivity watcher (see SCOPE HONESTY above) ---------------------- */
  function connectionKind() {
    const c = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    return c && c.type ? c.type : null;   // 'cellular' | 'wifi' | ... | null
  }

  function showOfflinePrompt() {
    const mins = Math.max(1, Math.round((Date.now() - offlineSince) / 60000));
    const kind = connectionKind();
    const cellHint = kind === "cellular"
      ? "Your last connection was mobile data, which makes this more notable. "
      : "";
    banner("pwa-offline",
      `<span><b>No connection for ~${mins} min.</b> ${cellHint}
       If your <b>phone also shows no mobile signal</b> and you didn't expect it,
       that is a warning sign of a SIM swap — call your operator
       (NTC 1498 · Ncell 9005 · Smart Cell 4242) and freeze your account.
       <span class="muted">This is a prompt, not a SIM check — SIMShield cannot read SIM state from a browser.</span></span>
       <span class="pwa-actions"><button class="subtle small" data-dismiss>Dismiss</button></span>`,
      "warn");
  }

  window.addEventListener("offline", () => {
    offlineSince = Date.now();
    clearTimeout(offlineTimer);
    offlineTimer = setTimeout(showOfflinePrompt, OFFLINE_PROMPT_AFTER_MS);
  });

  window.addEventListener("online", () => {
    clearTimeout(offlineTimer);
    offlineSince = null;
    const b = document.getElementById("pwa-offline");
    if (b) b.remove();
  });

  /* --- push opt-in ---------------------------------------------------------
     Registers a local push subscription so the browser can display alerts even
     when the tab is closed. A production deployment would send the subscription
     to the server and push via VAPID/FCM; here we expose the permission flow and
     let the notifier's simulated alerts surface locally.                     */
  window.simshieldEnablePush = async function enablePush() {
    if (!("Notification" in window)) return { ok: false, error: "Notifications unsupported on this browser." };
    const perm = await Notification.requestPermission();
    if (perm !== "granted") return { ok: false, error: "Notification permission was declined." };
    const reg = await navigator.serviceWorker.ready.catch(() => null);
    if (reg) {
      reg.showNotification("SIMShield alerts are on", {
        body: "You'll be warned here about risky sign-ins, SIM changes and held transactions — even if SMS is compromised.",
        icon: "/icons/icon-192.png",
        tag: "simshield-optin",
      });
    }
    localStorage.setItem("simshield_push", "1");
    return { ok: true };
  };

  window.simshieldPushEnabled = () =>
    "Notification" in window && Notification.permission === "granted";

  /* Deep link: ?chat=1 opens the floating assistant where one exists. */
  window.addEventListener("load", () => {
    if (new URLSearchParams(location.search).get("chat") === "1") {
      setTimeout(() => {
        const fab = document.getElementById("cb-fab");
        if (fab) fab.click();
      }, 400);
    }
  });
})();

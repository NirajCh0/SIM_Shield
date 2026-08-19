/* SIMShield — shared frontend helpers (session, fetch, nav, fingerprint). */
const API = ""; // same-origin (Flask serves this frontend)

/* --- session ------------------------------------------------------------------
   The session itself lives in an HttpOnly cookie the browser sends
   automatically — JavaScript cannot read it, so an XSS cannot steal it.
   What JS *does* handle is the CSRF token: a separate, readable cookie whose
   value must be echoed in X-CSRF-Token on every state-changing request. That
   double-submit pairing is what a cross-site request cannot forge.
   (See SECURITY_REMEDIATION.md findings F12/F13.) */
function readCookie(name) {
  const hit = document.cookie.split("; ").find((c) => c.startsWith(name + "="));
  return hit ? decodeURIComponent(hit.slice(name.length + 1)) : null;
}
const csrfToken = () => readCookie("simshield_csrf");

/* Legacy helpers kept so older pages keep working during the staged migration.
   getToken() no longer returns a bearer token — sessions are cookie-borne. */
const getToken = () => csrfToken();
const setToken = () => {};                 // no-op: the server sets the cookie
const clearToken = () => {};               // no-op: logout clears the cookie

function authHeaders(method = "GET") {
  const h = {};
  const t = csrfToken();
  if (t && !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase())) {
    h["X-CSRF-Token"] = t;
  }
  return h;
}

async function getJSON(path) {
  const r = await fetch(API + path, {
    credentials: "same-origin",
    headers: authHeaders("GET"),
  });
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).error || r.statusText);
  return r.json();
}
async function postJSON(path, body, method = "POST") {
  const r = await fetch(API + path, {
    method,
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", ...authHeaders(method) },
    body: JSON.stringify(body),
  });
  return { ok: r.ok, status: r.status, data: await r.json().catch(() => ({})) };
}

const el = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
const fmtWhen = (iso) => {
  if (!iso) return "";
  const d = new Date(iso.replace(" ", "T"));
  return isNaN(d) ? iso : d.toLocaleString("en-GB",
    { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" });
};

/* --- device fingerprint (privacy-light) ---------------------------------------
   A stable, non-invasive browser identifier: UA + platform + screen + timezone
   + a persisted random component. Only its salted HASH is ever stored
   server-side. Production would use a richer signal set (e.g. FingerprintJS). */
function deviceFingerprint() {
  let rand = localStorage.getItem("simshield_device_rand");
  if (!rand) {
    rand = Math.random().toString(36).slice(2) + Date.now().toString(36);
    localStorage.setItem("simshield_device_rand", rand);
  }
  const raw = [navigator.userAgent, navigator.platform, navigator.language,
               screen.width + "x" + screen.height,
               Intl.DateTimeFormat().resolvedOptions().timeZone, rand].join("|");
  let h = 0;
  for (let i = 0; i < raw.length; i++) { h = (h * 31 + raw.charCodeAt(i)) | 0; }
  return "fp-" + (h >>> 0).toString(16) + "-" + rand.slice(0, 8);
}

/* --- current user (cached per page load) ----------------------------------- */
let CURRENT_USER;
async function currentUser() {
  if (CURRENT_USER !== undefined) return CURRENT_USER;
  try { CURRENT_USER = (await getJSON("/api/auth/me")).user; }
  catch (_) { CURRENT_USER = null; }
  return CURRENT_USER;
}

async function logout() {
  try { await postJSON("/api/auth/logout", {}); } catch (_) {}
  clearToken();
  location.href = "/";
}

/* --- nav ------------------------------------------------------------------------
   Highlights the active link, fills the model-mode pill, and swaps the
   right-hand utility button between "Sign in" and the account menu. */
async function initNav(active) {
  document.querySelectorAll(".global-nav a.gn-link").forEach((a) => {
    if (a.dataset.page === active) a.classList.add("active");
  });
  try {
    const h = await getJSON("/api/health");
    const pill = el("#mode-pill");
    if (pill) {
      pill.textContent = h.ml_model_loaded
        ? (h.anomaly_model_loaded ? "rules + RF + IsoForest" : "ML + rules")
        : "rules-only";
      pill.classList.toggle("ok", h.ml_model_loaded);
    }
  } catch (_) {}
  const slot = el("#nav-auth");
  if (!slot) return;
  const u = await currentUser();
  if (u) {
    slot.innerHTML =
      `<a class="gn-utility" href="${u.role === "admin" ? "/admin" : "/dashboard"}">` +
      `${esc(u.display_name.split(" ")[0])}${u.role === "admin" ? " · Fraud desk" : ""}</a> ` +
      `<a class="gn-utility" href="#" id="gn-logout">Sign out</a>`;
    el("#gn-logout").addEventListener("click", (e) => { e.preventDefault(); logout(); });
  } else {
    slot.innerHTML = `<a class="gn-utility" href="/login">Sign in</a>`;
  }
}

/* decision -> colour for gauges */
const DEC_COLOR = { ALLOW: "#34c759", MONITOR: "#ffcc00", VERIFY: "#ff9500",
                    BLOCK: "#ff3b30", LOW: "#34c759", GUARDED: "#ffcc00",
                    ELEVATED: "#ff9500", HIGH: "#ff3b30", FROZEN: "#1d1d1f" };

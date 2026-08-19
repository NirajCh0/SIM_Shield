/* SIMShield app shell — one nav definition rendered on every page.
 *
 * The pages are plain static HTML with no build step, so nav markup used to be
 * duplicated per file and drifted. This renders the global nav, the sub-nav and
 * the mobile tab bar from a single source, marks the active page, and wires the
 * auth-aware account button.
 *
 * Usage in a page:  <script>renderShell("dashboard", "My security");</script>
 */

const NAV_PRIMARY = [
  { key: "home", href: "/", label: "Overview", icon: "home" },
  { key: "dashboard", href: "/dashboard", label: "Dashboard", icon: "chart", auth: true },
  { key: "money", href: "/money", label: "Exposure", icon: "wallet", auth: true },
  { key: "defence", href: "/defence", label: "Defence", icon: "shieldCheck", auth: true },
  { key: "awareness", href: "/awareness", label: "Awareness", icon: "book" },
  { key: "assistant", href: "/assistant", label: "Assistant", icon: "chat" },
];

const NAV_RESEARCH = [
  { key: "detection", href: "/detection", label: "Detection demo" },
  { key: "study", href: "/study", label: "User study" },
  { key: "metrics", href: "/metrics", label: "Evaluation" },
];

/* Bottom tab bar: max 5 items per the navigation guidelines. */
const TABS = [
  { key: "dashboard", href: "/dashboard", label: "Home", icon: "home" },
  { key: "money", href: "/money", label: "Exposure", icon: "wallet" },
  { key: "defence", href: "/defence", label: "Defence", icon: "shieldCheck" },
  { key: "awareness", href: "/awareness", label: "Learn", icon: "book" },
  { key: "assistant", href: "/assistant", label: "Ask", icon: "chat" },
];

function renderShell(active, subtitle, opts = {}) {
  const mount = document.getElementById("shell") || document.body;
  const nav = document.createElement("div");
  nav.innerHTML = `
    <nav class="global-nav">
      <div class="gn-inner">
        <a class="gn-brand" href="/">${icon("shieldCheck", 17)}<span>SIMShield</span></a>
        ${NAV_PRIMARY.map((n) => `<a class="gn-link${n.key === active ? " active" : ""}"
            href="${n.href}">${n.label}</a>`).join("")}
        <span class="gn-spacer"></span>
        <span class="gn-pill" id="mode-pill">…</span>
        <span id="nav-auth"></span>
      </div>
    </nav>
    ${subtitle === null ? "" : `
    <div class="sub-nav">
      <div class="sn-inner">
        <span class="sn-title">${subtitle || ""}</span>
        <span class="sn-links">
          ${(opts.links || NAV_RESEARCH).map((l) =>
            `<a href="${l.href}">${l.label}</a>`).join("")}
          ${opts.cta ? `<a class="btn small" href="${opts.cta.href}">${opts.cta.label}</a>` : ""}
        </span>
      </div>
    </div>`}
  `;
  mount.insertBefore(nav, mount.firstChild);

  // Marketing/auth pages pass tabs:false — a bottom app bar on a landing page
  // would advertise destinations a signed-out visitor can't reach.
  if (opts.tabs !== false) {
    const bar = document.createElement("nav");
    bar.className = "tabbar";
    bar.setAttribute("aria-label", "Main");
    bar.innerHTML = TABS.map((t) => `
      <a class="tab${t.key === active ? " active" : ""}" href="${t.href}"
         ${t.key === active ? 'aria-current="page"' : ""}>
        <span class="ic-wrap">${icon(t.icon, 22)}</span>${t.label}</a>`).join("");
    document.body.appendChild(bar);
    document.body.classList.add("has-tabbar");
  }

  initNav(active);
}

/* Scroll-reveal: elements with .reveal fade/slide in once, staggered.
   Fully skipped when the user prefers reduced motion. */
function initReveal() {
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const items = document.querySelectorAll(".reveal");
  if (reduce || !("IntersectionObserver" in window)) {
    items.forEach((el) => el.classList.add("in"));
    return;
  }
  const io = new IntersectionObserver((entries) => {
    entries.forEach((e) => {
      if (!e.isIntersecting) return;
      const group = e.target.parentElement;
      const sibs = group ? [...group.querySelectorAll(".reveal")] : [e.target];
      const i = Math.max(0, sibs.indexOf(e.target));
      e.target.style.transitionDelay = Math.min(i * 60, 300) + "ms";
      e.target.classList.add("in");
      io.unobserve(e.target);
    });
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  items.forEach((el) => io.observe(el));
}

/* Count a number up to its target — used on dashboard stat tiles. */
function countUp(el, to, opts = {}) {
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const fmt = opts.format || ((v) => Math.round(v).toLocaleString());
  if (reduce) { el.textContent = fmt(to); return; }
  const dur = opts.duration || 700;
  const from = 0;
  const t0 = performance.now();
  function step(t) {
    const p = Math.min(1, (t - t0) / dur);
    const eased = 1 - Math.pow(1 - p, 3);          // ease-out cubic
    el.textContent = fmt(from + (to - from) * eased);
    if (p < 1) requestAnimationFrame(step);
  }
  requestAnimationFrame(step);
}

/* --- scroll progress bar ---------------------------------------------------- */
function initScrollProgress() {
  if (document.querySelector(".scroll-progress")) return;
  const bar = document.createElement("div");
  bar.className = "scroll-progress";
  document.body.appendChild(bar);
  let ticking = false;
  const update = () => {
    const h = document.documentElement.scrollHeight - window.innerHeight;
    bar.style.width = (h > 0 ? (window.scrollY / h) * 100 : 0) + "%";
    ticking = false;
  };
  addEventListener("scroll", () => {
    if (!ticking) { requestAnimationFrame(update); ticking = true; }
  }, { passive: true });
  update();
}

/* --- parallax ----------------------------------------------------------------
   Elements with .parallax drift slightly against the scroll. Uses transform
   only (no layout), is rAF-throttled, and is skipped entirely for users who
   prefer reduced motion or on small screens where it just costs battery. */
function initParallax() {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  if (innerWidth < 834) return;
  const items = [...document.querySelectorAll(".parallax")];
  if (!items.length) return;
  let ticking = false;
  const update = () => {
    const mid = innerHeight / 2;
    items.forEach((el) => {
      const r = el.getBoundingClientRect();
      if (r.bottom < -200 || r.top > innerHeight + 200) return;
      const depth = parseFloat(el.dataset.depth || "0.06");
      el.style.transform = `translate3d(0, ${((r.top + r.height / 2) - mid) * -depth}px, 0)`;
    });
    ticking = false;
  };
  addEventListener("scroll", () => {
    if (!ticking) { requestAnimationFrame(update); ticking = true; }
  }, { passive: true });
  addEventListener("resize", update, { passive: true });
  update();
}

/* --- page transitions ---------------------------------------------------------
   Fade out before a same-origin navigation so pages hand over smoothly instead
   of flashing white. Ignores new-tab clicks, downloads, hashes and the tab bar
   (which should feel instant, like a native app). */
function initPageTransitions() {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
  document.addEventListener("click", (e) => {
    const a = e.target.closest("a");
    if (!a) return;
    const href = a.getAttribute("href") || "";
    if (a.target === "_blank" || a.hasAttribute("download")) return;
    if (!href.startsWith("/") || href.startsWith("//")) return;
    if (href.startsWith("/api/")) return;
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    if (a.closest(".tabbar")) return;
    e.preventDefault();
    document.body.classList.add("leaving");
    setTimeout(() => { location.href = href; }, 150);
  });
  // restore on bfcache back-navigation
  addEventListener("pageshow", (e) => {
    if (e.persisted) document.body.classList.remove("leaving");
  });
}

/* Standard page bootstrap: icons, art, reveal, scroll effects. */
function bootPage() {
  hydrateIcons();
  hydrateArt();
  initReveal();
  initScrollProgress();
  initParallax();
  initPageTransitions();
}

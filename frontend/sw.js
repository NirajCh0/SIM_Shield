/* SIMShield service worker — offline shell, push alerts, cache hygiene.
 *
 * Strategy:
 *   static shell   -> cache-first  (fast launch, works offline)
 *   API requests   -> network-only (security data must never be served stale)
 *   navigations    -> network-first, falling back to the cached page, then
 *                     offline.html — so the awareness/recovery guidance is
 *                     still reachable when the user has no connectivity, which
 *                     is exactly the situation a SIM-swap victim is in.
 */
// Bump VERSION whenever the shell list OR any cached asset changes —
// activate() purges every cache that is not this version.
//
// v3: page scripts were being served from cache FOREVER. The old fetch handler
// was cache-first with no revalidation, so once a browser had fetched
// `detection.page.js` it kept the stale copy until the version changed by hand.
// A fix to any page script was therefore invisible to every returning visitor —
// which is how a corrected `/detection` page still rendered blank. Static assets
// now use stale-while-revalidate (below), so a fix lands on the next load
// without anyone clearing site data.
const VERSION = "simshield-v3";
const SHELL = [
  "/",
  "/dashboard",
  "/money",
  "/defence",
  "/awareness",
  "/assistant",
  "/login",
  "/offline.html",
  "/style.css",
  "/script.js",
  "/icons.js",
  "/illustrations.js",
  "/shell.js",
  "/pwa.js",
  "/manifest.webmanifest",
  "/icons/icon-192.png",
  "/icons/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(VERSION)
      // addAll rejects the whole batch if any one request fails, so add
      // individually and tolerate misses (e.g. a page behind auth).
      .then((cache) => Promise.all(SHELL.map((u) => cache.add(u).catch(() => null))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Never cache the API: a stale risk score or alert list would be dangerous.
  if (url.pathname.startsWith("/api/")) return;

  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(VERSION).then((c) => c.put(req, copy)).catch(() => {});
          return res;
        })
        .catch(() => caches.match(req).then((hit) => hit || caches.match("/offline.html")))
    );
    return;
  }

  // Static assets: STALE-WHILE-REVALIDATE, not cache-first.
  //
  // Cache-first keeps the app fast and offline-capable, but it also pins a
  // stale script indefinitely: the revalidation only ran on a cache MISS, so a
  // corrected page script never reached a browser that had already cached the
  // broken one. The network request below is started on every request whether
  // or not there was a hit, so the cache is refreshed in the background and the
  // fix applies on the next load — offline still works, because the cached copy
  // is what gets served right now.
  event.respondWith(
    caches.match(req).then((hit) => {
      const fresh = fetch(req)
        .then((res) => {
          if (res.ok) {
            const copy = res.clone();
            caches.open(VERSION).then((c) => c.put(req, copy)).catch(() => {});
          }
          return res;
        })
        .catch(() => hit);          // offline: fall back to whatever we have
      return hit || fresh;
    })
  );
});

/* Push alerts — the out-of-band channel that still reaches a subscriber whose
   phone number has been hijacked (SMS goes to the attacker; push does not). */
self.addEventListener("push", (event) => {
  let data = { title: "SIMShield alert", body: "Open the app to review your account." };
  try {
    if (event.data) data = { ...data, ...event.data.json() };
  } catch (_) {
    if (event.data) data.body = event.data.text();
  }
  event.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: "/icons/icon-192.png",
      badge: "/icons/icon-192.png",
      tag: data.tag || "simshield-alert",
      renotify: true,
      requireInteraction: data.severity === "critical",
      data: { url: data.url || "/dashboard" },
    })
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const target = (event.notification.data && event.notification.data.url) || "/dashboard";
  event.waitUntil(
    self.clients.matchAll({ type: "window", includeUncontrolled: true }).then((list) => {
      for (const c of list) {
        if (c.url.includes(target) && "focus" in c) return c.focus();
      }
      return self.clients.openWindow(target);
    })
  );
});

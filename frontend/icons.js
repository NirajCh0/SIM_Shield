/* SIMShield icon system — inline SVG, Lucide-style geometry.
 *
 * One family, 1.75 stroke, 24×24 grid, `currentColor` fill so icons inherit
 * text colour and theme automatically. Replaces the emoji that were previously
 * used as structural icons: emoji render differently per platform, can't be
 * themed, and read as unprofessional in a banking UI.
 *
 * Usage:  icon("shield")            -> <svg> string
 *         icon("shield", 20)        -> sized
 *         icon("shield", 20, "cls") -> extra class
 */
const ICON_PATHS = {
  // navigation
  home: '<path d="M3 10.5 12 3l9 7.5"/><path d="M5 9.5V21h14V9.5"/>',
  shield: '<path d="M12 3 4.5 6v6c0 4.5 3.2 7.9 7.5 9 4.3-1.1 7.5-4.5 7.5-9V6L12 3Z"/>',
  shieldCheck: '<path d="M12 3 4.5 6v6c0 4.5 3.2 7.9 7.5 9 4.3-1.1 7.5-4.5 7.5-9V6L12 3Z"/><path d="m9 12 2 2 4-4"/>',
  wallet: '<path d="M3 7.5A2.5 2.5 0 0 1 5.5 5H18a2 2 0 0 1 2 2v1"/><path d="M3 7.5V17a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2H5.5A2.5 2.5 0 0 1 3 7.5Z"/><circle cx="16.5" cy="14" r="1.2"/>',
  book: '<path d="M4 5a2 2 0 0 1 2-2h12v16H6a2 2 0 0 0-2 2V5Z"/><path d="M8 7h7M8 11h7"/>',
  chat: '<path d="M20 12a7 7 0 0 1-7 7H8l-4 3v-4.5A7 7 0 0 1 8 5h5a7 7 0 0 1 7 7Z"/><path d="M9 11h6M9 14h4"/>',
  chart: '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
  // status / security
  alert: '<path d="M12 4.5 2.8 20h18.4L12 4.5Z"/><path d="M12 10v4M12 17.2v.1"/>',
  bell: '<path d="M18 9a6 6 0 1 0-12 0c0 5-2 6-2 6h16s-2-1-2-6Z"/><path d="M10.5 20a1.8 1.8 0 0 0 3 0"/>',
  lock: '<rect x="4.5" y="10.5" width="15" height="10" rx="2"/><path d="M8 10.5V7a4 4 0 0 1 8 0v3.5"/>',
  snowflake: '<path d="M12 3v18M4.2 7.5l15.6 9M19.8 7.5l-15.6 9"/><path d="m9.5 4.8 2.5 2.4 2.5-2.4M9.5 19.2l2.5-2.4 2.5 2.4"/>',
  key: '<circle cx="8" cy="14" r="4"/><path d="m11 11 8-8 2 2-2 2 2 2-2.5 2.5L16 9.5"/>',
  eye: '<path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z"/><circle cx="12" cy="12" r="3"/>',
  // device / telecom
  sim: '<path d="M6 3.5h7.5L19 9v11.5H6V3.5Z"/><rect x="9" y="11" width="7" height="6" rx="1"/><path d="M12.5 11v6"/>',
  phone: '<rect x="6.5" y="2.5" width="11" height="19" rx="2.5"/><path d="M10.5 18.5h3"/>',
  signalOff: '<path d="M3 20h.01M8 20v-4M13 20V11M18 20V5"/><path d="m3 3 18 18"/>',
  pin: '<path d="M12 21s7-6 7-11a7 7 0 1 0-14 0c0 5 7 11 7 11Z"/><circle cx="12" cy="10" r="2.5"/>',
  monitor: '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
  // actions
  check: '<path d="m5 13 4 4 10-10"/>',
  x: '<path d="M6 6 18 18M18 6 6 18"/>',
  arrowRight: '<path d="M5 12h14M13 6l6 6-6 6"/>',
  send: '<path d="M21 3 10.5 13.5"/><path d="M21 3 14.5 21l-4-7.5L3 9.5 21 3Z"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5.2l3.2 2"/>',
  trophy: '<path d="M8 4h8v5a4 4 0 0 1-8 0V4Z"/><path d="M8 5.5H5.5A2.5 2.5 0 0 0 8 10M16 5.5h2.5A2.5 2.5 0 0 1 16 10"/><path d="M10 13.2V16h4v-2.8M8.5 20h7"/>',
  target: '<circle cx="12" cy="12" r="8.5"/><circle cx="12" cy="12" r="4.5"/><circle cx="12" cy="12" r="1"/>',
  sparkle: '<path d="M12 3.5 13.6 9 19 10.5 13.6 12 12 17.5 10.4 12 5 10.5 10.4 9 12 3.5Z"/>',
  users: '<circle cx="9.5" cy="8.5" r="3.5"/><path d="M3 20c0-3.3 2.9-5.5 6.5-5.5S16 16.7 16 20"/><path d="M17 5.5a3.5 3.5 0 0 1 0 6.8M18 20c0-2.4-.9-4.1-2.4-5.1"/>',
  logout: '<path d="M14 4h4a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-4"/><path d="M10 16 6 12l4-4M6 12h9"/>',
  refresh: '<path d="M20 11a8 8 0 1 0-1.5 6"/><path d="M20 5v6h-6"/>',
  download: '<path d="M12 4v11M8 12l4 4 4-4"/><path d="M5 20h14"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M12 2.5v2.6M12 18.9v2.6M21.5 12h-2.6M5.1 12H2.5M18.7 5.3l-1.9 1.9M7.2 16.8l-1.9 1.9M18.7 18.7l-1.9-1.9M7.2 7.2 5.3 5.3"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8v.1"/>',
  play: '<path d="M8 5.5 18 12 8 18.5v-13Z"/>',
};

function icon(name, size = 20, cls = "") {
  const d = ICON_PATHS[name] || ICON_PATHS.info;
  return `<svg class="ic ${cls}" width="${size}" height="${size}" viewBox="0 0 24 24"
    fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round"
    stroke-linejoin="round" aria-hidden="true" focusable="false">${d}</svg>`;
}

/* Replace any [data-icon="name"] placeholder in the DOM with its SVG. */
function hydrateIcons(root = document) {
  root.querySelectorAll("[data-icon]").forEach((el) => {
    const size = parseInt(el.dataset.iconSize || "20", 10);
    el.innerHTML = icon(el.dataset.icon, size);
    el.removeAttribute("data-icon");
  });
}

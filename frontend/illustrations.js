/* SIMShield illustrations — inline animated SVG.
 *
 * Deliberately NOT bitmap images or CDN art:
 *   · the app is an offline-capable PWA, so assets must be self-contained
 *   · SVG scales crisply on every density and inherits the theme palette
 *   · motion is CSS-driven, so `prefers-reduced-motion` disables it for free
 *   · no third-party licensing to clear for an academic deliverable
 *
 * Each illustration teaches something about the attack rather than decorating.
 */

/* 1. A SIM card, drawn from life: bevelled corner, gold contact pad with the
      characteristic ISO-7816 trace pattern, subtle card texture. */
const ART_SIMCARD = `
<svg viewBox="0 0 320 200" class="art" role="img" aria-label="A SIM card showing its gold contact pad">
  <defs>
    <linearGradient id="simBody" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0%" stop-color="var(--primary)" stop-opacity=".85"/>
      <stop offset="100%" stop-color="var(--primary)" stop-opacity=".55"/>
    </linearGradient>
    <linearGradient id="simGold" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#e8c374"/>
      <stop offset="55%" stop-color="#d4a94e"/>
      <stop offset="100%" stop-color="#bf9338"/>
    </linearGradient>
    <pattern id="simWeave" width="4" height="4" patternUnits="userSpaceOnUse">
      <path d="M0 4 4 0" stroke="#fff" stroke-opacity=".14" stroke-width="1"/>
    </pattern>
  </defs>
  <g class="a-fade">
    <path d="M40 20h216a8 8 0 0 1 8 8v144a8 8 0 0 1-8 8H40a8 8 0 0 1-8-8V60l40-40Z"
          fill="url(#simBody)"/>
    <path d="M40 20h216a8 8 0 0 1 8 8v144a8 8 0 0 1-8 8H40a8 8 0 0 1-8-8V60l40-40Z"
          fill="url(#simWeave)"/>
    <path d="M112 34h132v132H112z" fill="none" stroke="#fff" stroke-opacity=".38"
          stroke-width="2.5" rx="10" ry="10"/>
  </g>
  <g class="a-fade" style="--d:220ms">
    <rect x="136" y="58" width="92" height="84" rx="7" fill="url(#simGold)"/>
    <g stroke="#8d6b24" stroke-width="2.4" fill="none" stroke-linecap="round">
      <path d="M136 100h30M198 100h30"/>
      <path d="M166 58v14M166 128v14M198 58v14M198 128v14"/>
      <path d="M152 76h14v18h-14zM198 76h16v18h-16z"/>
      <path d="M152 106h14v18h-14zM198 106h16v18h-16z"/>
      <path d="m178 58 4 18-4 8 4 8-4 18"/>
    </g>
    <rect x="136" y="58" width="92" height="84" rx="7" fill="none"
          stroke="#a3801f" stroke-width="1.4"/>
  </g>
  <g class="a-scan"><rect x="136" y="58" width="92" height="10" fill="#fff" opacity=".28" rx="5"/></g>
</svg>`;

/* 2. The theft, told in one picture: the victim's SIM on the left bleeding
      money and identity to the attacker's SIM on the right. */
const ART_THEFT = `
<svg viewBox="0 0 420 240" class="art" role="img" aria-label="Money and identity moving from the victim's SIM card to an attacker's SIM card">
  <defs>
    <marker id="thArrow" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
      <path d="M0 0 8 4 0 8Z" fill="var(--danger)"/>
    </marker>
  </defs>

  <!-- victim SIM -->
  <g class="a-fade">
    <path d="M28 52h96a8 8 0 0 1 8 8v120a8 8 0 0 1-8 8H28a8 8 0 0 1-8-8V80l28-28Z"
          fill="var(--primary)" opacity=".14" stroke="var(--primary)" stroke-width="2.5"/>
    <rect x="46" y="92" width="56" height="52" rx="6" fill="var(--primary)" opacity=".35"/>
    <g stroke="var(--primary)" stroke-width="2" fill="none" opacity=".8">
      <path d="M46 118h18M84 118h18M74 92v52"/>
    </g>
    <text x="76" y="176" text-anchor="middle" font-size="12" fill="currentColor" opacity=".7">Your number</text>
  </g>

  <!-- attacker SIM -->
  <g class="a-fade" style="--d:600ms">
    <path d="M296 52h96a8 8 0 0 1 8 8v120a8 8 0 0 1-8 8h-96a8 8 0 0 1-8-8V80l28-28Z"
          fill="var(--danger)" opacity=".12" stroke="var(--danger)" stroke-width="2.5"/>
    <rect x="314" y="92" width="56" height="52" rx="6" fill="var(--danger)" opacity=".28"/>
    <g stroke="var(--danger)" stroke-width="2" fill="none" opacity=".85">
      <path d="M314 118h18M352 118h18M342 92v52"/>
    </g>
    <text x="344" y="176" text-anchor="middle" font-size="12" fill="var(--danger)">Attacker's SIM</text>
  </g>

  <!-- transfer path -->
  <path d="M142 118h134" stroke="var(--danger)" stroke-width="2.5"
        stroke-dasharray="8 8" marker-end="url(#thArrow)" class="a-dash"/>

  <!-- travelling tokens -->
  <g class="a-travel-a">
    <circle r="15" fill="var(--danger)"/>
    <text y="5" text-anchor="middle" font-size="13" font-weight="700" fill="#fff">₨</text>
  </g>
  <g class="a-travel-b">
    <rect x="-24" y="-12" width="48" height="24" rx="12" fill="var(--ink)"/>
    <text y="5" text-anchor="middle" font-size="11" font-weight="600" fill="#fff">OTP</text>
  </g>

  <!-- context chips -->
  <g class="a-fade" style="--d:900ms" font-size="11" fill="currentColor" opacity=".72">
    <rect x="20" y="10" width="104" height="26" rx="13" fill="currentColor" opacity=".07"/>
    <text x="72" y="27" text-anchor="middle">bank login</text>
    <rect x="150" y="10" width="120" height="26" rx="13" fill="currentColor" opacity=".07"/>
    <text x="210" y="27" text-anchor="middle">SMS code follows</text>
    <rect x="296" y="10" width="104" height="26" rx="13" fill="var(--danger)" opacity=".12"/>
    <text x="348" y="27" text-anchor="middle" fill="var(--danger)">account drained</text>
  </g>
</svg>`;

/* 3. The defence: a login reaching the gate, scored, refused before any OTP. */
const ART_GATE = `
<svg viewBox="0 0 320 180" class="art" role="img" aria-label="A login attempt reaching a shield that blocks it before any one-time code is sent">
  <circle cx="160" cy="92" r="58" fill="var(--primary)" opacity=".07" class="a-pulse"/>
  <circle cx="160" cy="92" r="44" fill="var(--primary)" opacity=".07" class="a-pulse" style="--d:600ms"/>
  <g class="a-fade" style="--d:120ms">
    <path d="M160 50 130 62v22c0 16 12 28 30 33 18-5 30-17 30-33V62l-30-12Z"
          fill="var(--primary)" opacity=".14" stroke="var(--primary)" stroke-width="2.5"/>
    <path d="m150 92 7 7 14-14" fill="none" stroke="var(--primary)" stroke-width="3"
          stroke-linecap="round" stroke-linejoin="round" class="a-draw"/>
  </g>
  <g class="a-fade" style="--d:340ms">
    <rect x="10" y="78" width="70" height="28" rx="14" fill="none" stroke="currentColor"
          stroke-width="2" opacity=".55"/>
    <text x="45" y="96" text-anchor="middle" font-size="10.5" fill="currentColor" opacity=".75">login</text>
    <path d="M84 92h24" stroke="currentColor" stroke-width="2" opacity=".45" stroke-dasharray="4 4"/>
  </g>
  <g class="a-fade" style="--d:760ms">
    <rect x="238" y="78" width="74" height="28" rx="14" fill="var(--danger)" opacity=".1"/>
    <text x="275" y="96" text-anchor="middle" font-size="10.5" fill="var(--danger)" font-weight="600">no OTP sent</text>
    <path d="M212 92h22" stroke="var(--danger)" stroke-width="2" stroke-dasharray="4 4"/>
    <path d="m218 86 6 6-6 6" fill="none" stroke="var(--danger)" stroke-width="2" opacity=".5"/>
  </g>
</svg>`;

/* 4. The symptom: bars dropping to nothing. */
const ART_SIGNAL = `
<svg viewBox="0 0 320 180" class="art" role="img" aria-label="Mobile signal bars dropping away to no service">
  <g transform="translate(96 44)">
    ${[0, 1, 2, 3].map((i) => `
      <rect x="${i * 34}" y="${64 - i * 18}" width="22" height="${18 + i * 18}" rx="4"
            fill="var(--primary)" opacity=".85" class="a-drop" style="--d:${i * 130}ms"/>`).join("")}
  </g>
  <text x="160" y="140" text-anchor="middle" font-size="13" fill="var(--danger)"
        font-weight="600" class="a-fade" style="--d:900ms">No Service</text>
  <text x="160" y="160" text-anchor="middle" font-size="11" fill="currentColor" opacity=".6"
        class="a-fade" style="--d:1050ms">the one sign you can see</text>
</svg>`;

/* 5. Fusion: four signals converging into one decision. */
const ART_FUSION = `
<svg viewBox="0 0 320 180" class="art" role="img" aria-label="Four detection signals converging into a single risk decision">
  ${[["rules", 34], ["behaviour", 70], ["forest", 106], ["anomaly", 142]].map(([label, y], i) => `
    <g class="a-fade" style="--d:${i * 110}ms">
      <rect x="14" y="${y - 12}" width="86" height="24" rx="12" fill="none"
            stroke="currentColor" stroke-width="1.6" opacity=".5"/>
      <text x="57" y="${y + 4}" text-anchor="middle" font-size="10" fill="currentColor"
            opacity=".8">${label}</text>
      <path d="M104 ${y}q40 0 56 ${88 - y}" fill="none" stroke="var(--primary)"
            stroke-width="1.8" opacity=".45" stroke-dasharray="5 5" class="a-dash"
            style="--d:${i * 110 + 200}ms"/>
    </g>`).join("")}
  <g class="a-fade" style="--d:640ms">
    <circle cx="228" cy="88" r="34" fill="var(--primary)" opacity=".1"/>
    <circle cx="228" cy="88" r="34" fill="none" stroke="var(--primary)" stroke-width="2.5"/>
    <text x="228" y="84" text-anchor="middle" font-size="17" font-weight="700"
          fill="var(--primary)">0–100</text>
    <text x="228" y="99" text-anchor="middle" font-size="9" fill="currentColor" opacity=".7">risk score</text>
  </g>
  <g class="a-fade" style="--d:860ms">
    <rect x="272" y="74" width="38" height="28" rx="14" fill="var(--ok)" opacity=".16"/>
    <text x="291" y="92" text-anchor="middle" font-size="9.5" font-weight="600" fill="#1d7a3f">allow</text>
  </g>
</svg>`;

/* 6. A phone raising a security alert. */
const ART_PHONE_ALERT = `
<svg viewBox="0 0 320 200" class="art" role="img" aria-label="A phone showing a security alert">
  <g class="a-fade">
    <rect x="112" y="18" width="96" height="164" rx="16" fill="none"
          stroke="currentColor" stroke-width="2.5" opacity=".8"/>
    <rect x="120" y="34" width="80" height="132" rx="6" fill="var(--primary)" opacity=".06"/>
    <rect x="146" y="24" width="28" height="5" rx="2.5" fill="currentColor" opacity=".35"/>
  </g>
  <g class="a-fade" style="--d:260ms">
    <circle cx="160" cy="82" r="24" fill="var(--danger)" opacity=".14"/>
    <path d="M160 70v16M160 94v.5" stroke="var(--danger)" stroke-width="3.5"
          stroke-linecap="round"/>
    <circle cx="160" cy="82" r="24" fill="none" stroke="var(--danger)" stroke-width="2"/>
  </g>
  <g class="a-fade" style="--d:420ms">
    <rect x="128" y="118" width="64" height="7" rx="3.5" fill="currentColor" opacity=".28"/>
    <rect x="128" y="132" width="48" height="7" rx="3.5" fill="currentColor" opacity=".18"/>
    <rect x="128" y="148" width="64" height="14" rx="7" fill="var(--primary)" opacity=".75"/>
  </g>
  <circle cx="160" cy="82" r="30" fill="none" stroke="var(--danger)" stroke-width="1.6"
          class="a-ring"/>
  <circle cx="160" cy="82" r="30" fill="none" stroke="var(--danger)" stroke-width="1.6"
          class="a-ring" style="--d:900ms"/>
</svg>`;

/* 7. The attack timeline — how fast it moves. */
const ART_TIMELINE = `
<svg viewBox="0 0 420 150" class="art" role="img" aria-label="Timeline of a SIM swap from operator change to account drained">
  <line x1="30" y1="86" x2="392" y2="86" stroke="currentColor" stroke-width="2" opacity=".2"/>
  <line x1="30" y1="86" x2="392" y2="86" stroke="var(--danger)" stroke-width="2.5"
        class="a-grow" stroke-linecap="round"/>
  ${[["SIM swapped", "14:02", 30, "var(--danger)"],
     ["signal lost", "14:05", 150, "var(--orange)"],
     ["OTP intercepted", "14:11", 270, "var(--danger)"],
     ["account drained", "14:26", 386, "var(--danger)"]].map(([label, time, x, c], i) => `
    <g class="a-fade" style="--d:${i * 260 + 300}ms">
      <circle cx="${x}" cy="86" r="7" fill="${c}"/>
      <circle cx="${x}" cy="86" r="12" fill="${c}" opacity=".2"/>
      <text x="${x}" y="${i % 2 ? 118 : 62}" text-anchor="middle" font-size="11"
            fill="currentColor" opacity=".85">${label}</text>
      <text x="${x}" y="${i % 2 ? 132 : 48}" text-anchor="middle" font-size="10"
            fill="currentColor" opacity=".45">${time}</text>
    </g>`).join("")}
</svg>`;

/* 8. The vault: what containment looks like once the alarm goes off. */
const ART_VAULT = `
<svg viewBox="0 0 320 190" class="art" role="img" aria-label="An account frozen behind a locked vault door">
  <g class="a-fade">
    <rect x="66" y="26" width="188" height="140" rx="14" fill="var(--primary)" opacity=".07"/>
    <rect x="66" y="26" width="188" height="140" rx="14" fill="none"
          stroke="var(--primary)" stroke-width="2.5"/>
    <circle cx="160" cy="96" r="44" fill="none" stroke="var(--primary)"
            stroke-width="2" opacity=".55"/>
    <circle cx="160" cy="96" r="30" fill="none" stroke="var(--primary)" stroke-width="2.5"
            class="a-spin"/>
    <g stroke="var(--primary)" stroke-width="3" stroke-linecap="round" class="a-spin">
      <path d="M160 66v-9M160 135v-9M130 96h-9M199 96h-9"/>
    </g>
  </g>
  <g class="a-fade" style="--d:380ms">
    <rect x="142" y="86" width="36" height="26" rx="5" fill="var(--primary)"/>
    <path d="M148 86v-7a12 12 0 0 1 24 0v7" fill="none" stroke="var(--primary)"
          stroke-width="3.5"/>
  </g>
  <text x="160" y="180" text-anchor="middle" font-size="12" fill="currentColor"
        opacity=".65" class="a-fade" style="--d:600ms">frozen — every transaction refused</text>
</svg>`;

const ILLUSTRATIONS = {
  simcard: ART_SIMCARD,
  theft: ART_THEFT,
  swap: ART_THEFT,          // alias — `swap` was the old name
  gate: ART_GATE,
  signal: ART_SIGNAL,
  fusion: ART_FUSION,
  alert: ART_PHONE_ALERT,
  timeline: ART_TIMELINE,
  vault: ART_VAULT,
};

function art(name) { return ILLUSTRATIONS[name] || ""; }

/* Fill any [data-art="name"] container. */
function hydrateArt(root = document) {
  root.querySelectorAll("[data-art]").forEach((el) => {
    el.innerHTML = art(el.dataset.art);
    el.removeAttribute("data-art");
  });
}

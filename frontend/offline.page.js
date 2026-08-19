/* offline.page.js — extracted from offline.html.
 * Page logic lives in an external same-origin file so the CSP can be
 * `script-src 'self'` with no 'unsafe-inline'. Do not re-inline this.
 *
 * The retry button previously used an inline onclick handler, which a strict
 * CSP blocks just as it blocks inline <script> blocks.
 */
hydrateIcons();

document.getElementById("btn-retry")
  .addEventListener("click", () => location.reload());

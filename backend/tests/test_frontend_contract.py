"""
Contract between the backend's vocabulary and the frontend's stylesheet/scripts.

WHY THIS FILE EXISTS
Two defects reached the working tree because nothing checked that the *served*
page could actually render what the *backend* emits:

  * `sev-${severity}` builds a CSS class from a backend value. The backend emits
    low/medium/high/critical for cases, but only `.sev-critical` existed —
    so three of the four severities rendered `.sev`'s white text on no
    background and were **invisible**.
  * `.table-wrap` was used in markup and defined nowhere, so wide tables
    overflowed the page instead of scrolling inside their container.

Neither is caught by a Python test of the API, by `node --check` (the files
parse fine), or by the CSP test (no inline scripts involved). They are the same
family as post-review correction C2: **the suite was green while the UI was
broken**, because every assertion was about configuration rather than about what
a browser would receive.

So this file asserts the join: every class the code can *construct* from a
backend enum has a rule, every helper the page code *calls* is defined by a
script the page actually loads, and every script tag resolves to a real file.
"""
import os
import re

import pytest

from engine import cases
from engine.config_loader import backend_path

FRONTEND = os.path.join(os.path.dirname(backend_path("")), "frontend")
if not os.path.isdir(FRONTEND):
    FRONTEND = os.path.abspath(
        os.path.join(os.path.dirname(backend_path("x")), "..", "frontend"))

PAGES = ["index.html", "login.html", "register.html", "dashboard.html",
         "money.html", "defence.html", "awareness.html", "assistant.html",
         "detection.html", "admin.html", "study.html", "metrics.html",
         "offline.html"]


def _read(name: str) -> str:
    with open(os.path.join(FRONTEND, name), encoding="utf-8") as f:
        return f.read()


@pytest.fixture(scope="module")
def stylesheet():
    return _read("style.css")


@pytest.fixture(scope="module")
def all_page_js():
    combined = ""
    for name in os.listdir(FRONTEND):
        if name.endswith(".js"):
            combined += _read(name) + "\n"
    return combined


# =============================================================================
# Backend vocabulary -> CSS classes
# =============================================================================
class TestSeverityClassesExist:

    @pytest.mark.parametrize("severity", cases.SEVERITIES)
    def test_every_case_severity_has_a_style(self, severity, stylesheet):
        """
        `sev-${c.severity}` is built from this exact list. A missing rule is an
        invisible chip, not a styling nitpick.
        """
        assert f".sev-{severity}" in stylesheet, (
            f"case severity {severity!r} renders as .sev-{severity}, which has "
            "no rule in style.css — the chip would be white on nothing")

    @pytest.mark.parametrize("severity", ["info", "warning", "critical"])
    def test_every_alert_severity_has_a_style(self, severity, stylesheet):
        assert f".sev-{severity}" in stylesheet

    def test_the_base_severity_chip_is_defined(self, stylesheet):
        assert re.search(r"\.sev\s*\{", stylesheet)


class TestStructuralClassesExist:

    @pytest.mark.parametrize("cls", [
        "table-scroll", "status-chip", "card", "muted", "small", "row",
        "grid", "cols-3", "btn", "ghost", "subtle", "hidden", "sec-head", "wrap",
    ])
    def test_class_used_in_markup_is_defined(self, cls, stylesheet):
        used = any(re.search(rf'class="[^"]*\b{re.escape(cls)}\b', _read(p))
                   for p in PAGES)
        if not used:
            pytest.skip(f"{cls} not used in any page")
        assert re.search(rf"\.{re.escape(cls)}\b", stylesheet), (
            f".{cls} is used in markup but has no rule in style.css")

    def test_classes_in_javascript_templates_also_exist(self):
        """
        Markup built inside a JS template literal is still markup.

        `class="table-wrap"` was fixed in the HTML but survived in
        `admin.page.js`, because the earlier version of this check only scanned
        `.html` files — so the fairness tables silently lost their horizontal
        scroll container. Half a check is how a fix looks complete and is not.
        """
        stylesheet = _read("style.css")
        # Classes that are structural (not utility one-offs) and could be typos.
        watched = {"table-scroll", "table-wrap", "status-chip", "sev", "card",
                   "banner", "empty", "item", "grow", "when", "kpi", "bar"}
        missing = []
        for script in _page_scripts():
            src = _read(script)
            for classes in re.findall(r'class="([a-z][a-z0-9 \-]*)"', src):
                for cls in classes.split():
                    if cls in watched and not re.search(
                            rf"\.{re.escape(cls)}\b", stylesheet):
                        missing.append(f"{script}: .{cls} has no rule")
        assert missing == [], "\n".join(sorted(set(missing)))

    def test_no_page_invents_a_button_variant_that_does_not_exist(self):
        """
        `class="btn secondary"` shipped once and rendered as a full primary
        CTA, because `.secondary` was never defined — the stylesheet's variants
        are ghost/subtle/small/danger. A button variant that silently falls back
        to the primary style is worse than an obvious break: "Remove" and
        "Withdraw" looked like the main action on the page.
        """
        defined = set(re.findall(r"(?:button|\.btn)\.([a-z]+)", _read("style.css")))
        defined |= {m for m in re.findall(r"^\.([a-z]+)\s*\{", _read("style.css"),
                                          re.MULTILINE)}
        used = set()
        for page in PAGES + [p.replace(".html", ".page.js") for p in PAGES]:
            path = os.path.join(FRONTEND, page)
            if not os.path.exists(path):
                continue
            for classes in re.findall(r'class="btn ([a-z ]+)"', _read(page)):
                used.update(classes.split())
        undefined = sorted(used - defined)
        assert undefined == [], f"button variants used but undefined: {undefined}"

    def test_wide_tables_scroll_inside_a_container(self, stylesheet):
        """The page body must never scroll sideways on a phone."""
        match = re.search(r"\.table-scroll\s*\{([^}]*)\}", stylesheet)
        assert match, ".table-scroll is missing"
        assert "overflow-x" in match.group(1)


# =============================================================================
# Page scripts resolve
# =============================================================================
class TestScriptsResolve:

    @pytest.mark.parametrize("page", PAGES)
    def test_every_script_tag_points_at_a_real_file(self, page):
        for src in re.findall(r'<script src="([^"]+)"', _read(page)):
            path = os.path.join(FRONTEND, src.lstrip("/"))
            assert os.path.exists(path), f"{page} loads missing script {src}"

    @pytest.mark.parametrize("page", ["defence.html", "admin.html"])
    def test_page_helpers_are_defined_by_a_loaded_script(self, page):
        """
        Every helper the page's own script CALLS must be defined by a script
        that page actually loads — not merely exist somewhere in the folder.
        `admin.html` does not load `shell.js`, so requiring `renderShell`
        everywhere would be wrong; the check follows what each page uses.
        """
        html = _read(page)
        loaded = ""
        for src in re.findall(r'<script src="([^"]+)"', html):
            loaded += _read(src.lstrip("/")) + "\n"
        script = _read(page.replace(".html", ".page.js"))
        for helper in ("getJSON", "postJSON", "esc", "el", "authHeaders",
                       "renderShell", "icon", "fmtWhen", "hydrateIcons",
                       "bootPage"):
            if not re.search(rf"\b{helper}\s*\(", script):
                continue                      # this page does not use it
            assert re.search(rf"(?:function|const|let|var)\s+{helper}\b", loaded), (
                f"{page} calls {helper}() but no script it loads defines it")

    @pytest.mark.parametrize("page", ["defence.html", "admin.html"])
    def test_element_ids_referenced_by_the_page_script_exist(self, page):
        """
        `g("case-rows")` returning null throws on the first `.innerHTML`, which
        kills the rest of the script — including sections that were fine.

        Ids the script itself injects (e.g. the freeze button, rendered into
        `freeze-action` at runtime) are excluded: those legitimately do not
        appear in the static markup.
        """
        html = _read(page)
        script_name = page.replace(".html", ".page.js")
        script = _read(script_name)
        ids = set(re.findall(r'\bg\("([a-z0-9-]+)"\)', script))
        injected = set(re.findall(r'id="([a-z0-9-]+)"', script))
        missing = [i for i in sorted(ids - injected) if f'id="{i}"' not in html]
        assert missing == [], f"{script_name} targets ids absent from {page}: {missing}"


# =============================================================================
# API response SHAPE matches what the page does with it
# =============================================================================
def _page_scripts() -> list[str]:
    return sorted(n for n in os.listdir(FRONTEND) if n.endswith(".page.js"))


def _get_json_calls(src: str) -> list[tuple[str, str | None]]:
    """
    Every `getJSON("<path>")` paired with the variable holding its result.

    Two assignment forms matter, and missing the second one is how this check
    would have become decorative — the real `/api/users` bug used it:

        const users = await getJSON("/api/users");
        const [groups, users] = await Promise.all([getJSON(a), getJSON(b)]);

    The destructured form is paired POSITIONALLY, which is what makes the
    second variable resolvable at all.
    """
    out: list[tuple[str, str | None]] = []
    claimed: set[int] = set()

    # Form 2 first: destructured Promise.all.
    for m in re.finditer(
            r'(?:const|let|var)\s*\[([^\]]+)\]\s*=\s*await\s+Promise\.all\(\s*\['
            r'(.*?)\]\s*\)', src, re.S):
        names = [n.strip() for n in m.group(1).split(",") if n.strip()]
        paths = re.findall(r'getJSON\("([^"]+)"\)', m.group(2))
        for i, path in enumerate(paths):
            out.append((path, names[i] if i < len(names) else None))
        for c in re.finditer(r'getJSON\("[^"]+"\)', m.group(2)):
            claimed.add(m.start(2) + c.start())

    # Form 1: a plain assignment, skipping any call already paired above.
    for m in re.finditer(
            r'(?:(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*)?'
            r'(?:await\s+)?getJSON\("([^"]+)"\)', src):
        call_start = src.index('getJSON("', m.start())
        if call_start in claimed:
            continue
        out.append((m.group(2), m.group(1)))
    return out


class TestApiShapeMatchesPageUsage:
    """
    The bug this exists for: `/api/users` was changed during the security
    remediation to return `{synthetic: true, profiles: [...]}` instead of a bare
    list, to label the data honestly. Two pages still called `users.map(...)`.

    `.map` is undefined on an object, so the whole load function threw — and
    because `bootPage()` runs at the END of that function, **`/detection`
    rendered as a completely blank page**. The API test passed, the CSP test
    passed, the page was dead.

    An API's response shape is part of its contract with the page. Changing it
    is a breaking change even when every backend test still passes.
    """

    @pytest.fixture()
    def admin_client(self, client, user_factory):
        """
        A signed-in admin, so admin endpoints report their real shape rather
        than a 401 error body — which is a dict, and would look exactly like
        the shape mismatch this class exists to detect.
        """
        user, password = user_factory(role="admin")
        r = client.post("/api/auth/login",
                        json={"email": user["email"], "password": password,
                              "fingerprint": "fp-shape"})
        body = r.get_json()
        otp = ((body.get("delivery") or {}).get("demo") or {}).get("otp")
        if not otp:
            pytest.skip("demo OTP not revealed in this environment")
        client.post("/api/auth/verify-otp",
                    json={"email": user["email"], "code": otp,
                          "challenge": body["challenge"], "fingerprint": "fp-shape"})
        return client

    @pytest.mark.parametrize("script", _page_scripts())
    def test_endpoints_mapped_over_return_a_json_array(self, script, admin_client):
        src = _read(script)
        failures = []
        for path, var in _get_json_calls(src):
            if not var or "${" in path:
                continue
            # Does the script call .map() on the value it just fetched?
            if not re.search(rf"\b{re.escape(var)}\.map\(", src):
                continue
            resp = admin_client.get(path)
            if resp.status_code != 200:
                continue                     # covered by the reachability test
            body = resp.get_json()
            if not isinstance(body, list):
                failures.append(
                    f"{script}: {path} returns {type(body).__name__} "
                    f"{list(body)[:4] if isinstance(body, dict) else ''} "
                    f"but the page calls {var}.map(...)")
        assert failures == [], "\n".join(failures)

    @pytest.mark.parametrize("script", _page_scripts())
    def test_every_endpoint_a_page_calls_exists(self, script, admin_client):
        """
        A page calling a route that 404s or 500s is a dead section. 401/403 are
        fine — those are pages that legitimately fetch before sign-in.
        """
        bad = []
        for path, _var in _get_json_calls(_read(script)):
            if "${" in path:
                continue
            status = admin_client.get(path).status_code
            if status not in (200, 401, 403):
                bad.append(f"{script}: {path} -> {status}")
        assert bad == [], "\n".join(bad)

    def test_the_detection_page_can_populate_its_profile_picker(self, client):
        """
        The specific regression, pinned: `/detection` is where the whole
        detection story is demonstrated, and it rendered blank.
        """
        body = client.get("/api/users").get_json()
        profiles = body.get("profiles") if isinstance(body, dict) else body
        assert isinstance(profiles, list) and profiles, "no synthetic profiles"
        assert {"user_id", "display_name", "operator", "sim_activation_date"} <= set(
            profiles[0]), "profile rows lack the fields the picker renders"
        src = _read("detection.page.js")
        assert "users.profiles || users" in src, (
            "detection.page.js must tolerate the {synthetic, profiles} wrapper")

    def test_the_register_page_can_populate_its_profile_picker(self, client):
        """
        `/register` offers "Link a demo telecom profile". It hit the same
        `/api/users` shape change as `/detection` and rendered an empty
        dropdown — silently, because the call sits in a bare `catch {}`.
        """
        src = _read("register.page.js")
        assert "users.profiles || users" in src, (
            "register.page.js must tolerate the {synthetic, profiles} wrapper")
        body = client.get("/api/users").get_json()
        profiles = body.get("profiles") if isinstance(body, dict) else body
        assert len(profiles) >= 10, "the demo profile picker would look empty"

    def test_the_service_worker_cannot_pin_a_stale_script_forever(self):
        """
        The reason a *fixed* page still rendered broken in a real browser.

        The old fetch handler was cache-first with revalidation only on a MISS,
        so a page script cached once was served until `VERSION` changed by hand.
        Every JS fix was invisible to returning visitors. Stale-while-revalidate
        keeps the offline guarantee while letting a fix land on the next load.
        """
        sw = _read("sw.js")
        assert "stale-while-revalidate" in sw.lower(), \
            "the static-asset strategy must revalidate, not pin"
        # The network request must be issued unconditionally, not only when the
        # cache misses — `hit || fetch(...)` is the bug, `hit || fresh` is the fix.
        assert re.search(r"return\s+hit\s*\|\|\s*fresh", sw), \
            "sw.js still short-circuits the network request on a cache hit"
        assert not re.search(r"hit\s*\|\|\s*fetch\(req\)", sw), \
            "sw.js reverted to cache-first with no background revalidation"

    def test_the_scenario_picker_receives_all_four_decision_groups(self, client):
        groups = client.get("/api/scenarios/grouped").get_json()
        assert isinstance(groups, list)
        assert {g["decision"] for g in groups} == {"ALLOW", "MONITOR", "VERIFY", "BLOCK"}
        assert all(len(g["scenarios"]) == 10 for g in groups), \
            "the detection page advertises ten demos per decision class"


# =============================================================================
# The new sections are actually wired into the pages
# =============================================================================
class TestNewSectionsArePresent:

    def test_defence_offers_passkeys_and_recovery_codes(self):
        html = _read("defence.html")
        assert 'id="add-passkey"' in html
        assert 'id="gen-recovery"' in html

    def test_defence_offers_an_appeal(self):
        assert 'id="submit-appeal"' in _read("defence.html")

    def test_admin_has_the_case_queue_and_reason_code_selector(self):
        html = _read("admin.html")
        assert 'id="case-rows"' in html
        assert 'id="case-reason"' in html

    def test_admin_has_the_appeals_queue_and_monitoring(self):
        html = _read("admin.html")
        assert 'id="appeal-rows"' in html
        assert 'id="fairness-box"' in html

    def test_the_ui_states_the_attestation_limitation(self):
        """A limitation the docs admit must also reach the person using it."""
        assert "attestation" in _read("defence.html").lower()

    def test_the_ui_states_that_fairness_cohorts_are_synthetic(self):
        """The warning is rendered from the API payload, not hardcoded."""
        assert 'id="monitoring-warning"' in _read("admin.html")

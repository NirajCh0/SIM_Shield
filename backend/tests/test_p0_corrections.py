"""
Regression tests for three P0 defects found by source review after the first
remediation pass. Each existed because the original tests asserted on
configuration rather than on what the application actually does.

C1  app.py still called `app.run(debug=True)`. The old test only checked
    `settings.debug_enabled()` in isolation, never the real entry point.
C2  The CSP promised `script-src 'self' 'nonce-…'` but no <script> tag carried
    a nonce, so a real browser would have blocked every page script. The old
    test asserted the header string and never the served HTML.
C3  Login responses returned `token` and `csrf_token` in the JSON body, handing
    JavaScript exactly what the HttpOnly cookie exists to withhold.
"""
import os
import re

import pytest

FRONTEND = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "frontend")

PAGES = ["/", "/dashboard", "/money", "/defence", "/awareness", "/assistant",
         "/detection", "/login", "/register", "/admin", "/study", "/metrics",
         "/offline.html"]

INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>", re.I)
INLINE_HANDLER = re.compile(r"\son(?:click|load|error|submit|change|input|"
                            r"mouseover|focus|blur|keydown|keyup)\s*=", re.I)


# ============================================================================
# C1 — the real entry point must not enable the debugger
# ============================================================================
class TestEntryPointDebug:
    def test_run_config_debug_is_false_by_default(self):
        """Assert on the ACTUAL kwargs app.py would pass to app.run()."""
        import app as appmod
        cfg = appmod.run_config()
        assert cfg["debug"] is False
        assert cfg["use_reloader"] is False

    def test_main_invokes_run_with_debug_false(self, monkeypatch):
        """Drive main() and capture what it really hands to Flask."""
        import app as appmod
        captured = {}
        monkeypatch.setattr(appmod.app, "run",
                            lambda **kw: captured.update(kw))
        monkeypatch.setattr(appmod.compliance, "enforce_retention", lambda: {})
        appmod.main()
        assert captured, "main() did not call app.run()"
        assert captured["debug"] is False, \
            f"entry point would start with debug={captured['debug']}"
        assert captured["use_reloader"] is False

    def test_source_contains_no_hardcoded_debug_true(self):
        """Belt and braces: the literal must not reappear in app.py."""
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.py")
        source = open(path, encoding="utf-8").read()
        assert "debug=True" not in source.replace(" ", "")

    def test_debug_still_impossible_outside_development(self, monkeypatch):
        import app as appmod
        from engine import settings
        monkeypatch.setattr(settings, "is_development", lambda: False)
        monkeypatch.setenv("SIMSHIELD_DEBUG", "true")
        assert appmod.run_config()["debug"] is False


# ============================================================================
# C2 — CSP must match reality: no inline scripts anywhere
# ============================================================================
class TestCspMatchesServedHtml:
    @pytest.mark.parametrize("path", PAGES)
    def test_served_page_has_no_inline_script(self, client, path):
        html = client.get(path).get_data(as_text=True)
        found = INLINE_SCRIPT.findall(html)
        assert not found, (
            f"{path} contains {len(found)} inline <script> block(s); the CSP "
            f"has no 'unsafe-inline', so a browser would block them")

    @pytest.mark.parametrize("path", PAGES)
    def test_served_page_has_no_inline_event_handler(self, client, path):
        html = client.get(path).get_data(as_text=True)
        found = INLINE_HANDLER.findall(html)
        assert not found, f"{path} uses inline event handler(s) {found}"

    def test_csp_script_src_is_self_only(self, client):
        csp = client.get("/login").headers["Content-Security-Policy"]
        script = [d.strip() for d in csp.split(";")
                  if d.strip().startswith("script-src")][0]
        assert script == "script-src 'self'", script
        assert "unsafe-inline" not in script
        assert "unsafe-eval" not in script

    def test_every_script_the_login_page_loads_is_same_origin_and_200(self, client):
        """
        The functional half: under this CSP the page only works if every script
        it references is same-origin AND actually served.
        """
        html = client.get("/login").get_data(as_text=True)
        srcs = re.findall(r'<script[^>]*\bsrc="([^"]+)"', html)
        assert srcs, "login page loads no scripts at all"
        for src in srcs:
            assert not re.match(r"https?://", src), f"{src} is cross-origin"
            r = client.get(src if src.startswith("/") else "/" + src)
            assert r.status_code == 200, f"{src} -> {r.status_code}"
            assert "javascript" in r.headers.get("Content-Type", "").lower()

    def test_login_page_logic_is_present_in_its_external_file(self, client):
        """Guards against an extraction that dropped the page's behaviour."""
        js = client.get("/login.page.js").get_data(as_text=True)
        for symbol in ("doLogin", "doVerify", "pendingChallenge", "btn-login"):
            assert symbol in js, f"login.page.js lost {symbol}"

    def test_no_page_js_file_was_left_behind_unreferenced(self, client):
        """Every extracted *.page.js must be referenced by exactly its page."""
        for name in os.listdir(FRONTEND):
            if not name.endswith(".page.js"):
                continue
            page = "/" + name.replace(".page.js", "")
            page = "/" if page == "/index" else page
            if page == "/offline":
                page = "/offline.html"
            html = client.get(page).get_data(as_text=True)
            assert name in html, f"{name} is not referenced by {page}"


# ============================================================================
# C3 — tokens must travel only in cookies
# ============================================================================
class TestNoTokensInResponseBodies:
    def test_login_response_leaks_no_tokens(self, client, user_factory):
        user, password = user_factory()
        r = client.post("/api/auth/login",
                        json={"email": user["email"], "password": password,
                              "fingerprint": "fp-c3"})
        body = r.get_json()
        assert "token" not in body
        assert "csrf_token" not in body
        raw = r.get_data(as_text=True)
        assert "csrf_token" not in raw

    def test_verify_otp_response_leaks_no_tokens(self, client, user_factory):
        user, password = user_factory()
        start = client.post("/api/auth/login",
                            json={"email": user["email"], "password": password,
                                  "fingerprint": "fp-c3b"}).get_json()
        r = client.post("/api/auth/verify-otp",
                        json={"email": user["email"],
                              "code": start["delivery"]["demo"]["otp"],
                              "challenge": start["challenge"],
                              "fingerprint": "fp-c3b"})
        body = r.get_json()
        assert r.status_code == 200
        assert "token" not in body, "session token must not be in the body"
        assert "csrf_token" not in body, "CSRF token must not be in the body"
        assert body["ok"] is True and "user" in body

    def test_session_cookie_is_httponly_and_samesite(self, client, user_factory):
        user, password = user_factory()
        start = client.post("/api/auth/login",
                            json={"email": user["email"], "password": password,
                                  "fingerprint": "fp-c3c"}).get_json()
        r = client.post("/api/auth/verify-otp",
                        json={"email": user["email"],
                              "code": start["delivery"]["demo"]["otp"],
                              "challenge": start["challenge"],
                              "fingerprint": "fp-c3c"})
        cookies = r.headers.getlist("Set-Cookie")
        session = [c for c in cookies if c.startswith("simshield_session=")]
        csrf = [c for c in cookies if c.startswith("simshield_csrf=")]
        assert session, "no session cookie was set"
        assert "HttpOnly" in session[0]
        assert "SameSite=Lax" in session[0]
        assert csrf, "no CSRF cookie was set"
        # The CSRF cookie must be readable by JS — that is how double-submit works.
        assert "HttpOnly" not in csrf[0]

    def test_authenticated_request_works_from_cookies_alone(self, client, signed_in):
        """
        End-to-end proof the flow still functions with tokens removed from the
        body: the fixture reads CSRF from the cookie jar, exactly as a page does.
        """
        _, headers = signed_in()
        assert client.get("/api/me/dashboard").status_code == 200      # cookie only
        r = client.post("/api/me/transactions", headers=headers,
                        json={"amount": 25, "merchant": "cookie-auth test"})
        assert r.status_code in (200, 403)
        assert r.get_json().get("simulation_only") is True

    def test_state_change_without_csrf_header_is_rejected(self, client, signed_in):
        signed_in()
        r = client.post("/api/me/transactions",
                        json={"amount": 25, "merchant": "no csrf"})
        assert r.status_code == 403
        assert "CSRF" in r.get_json()["error"]

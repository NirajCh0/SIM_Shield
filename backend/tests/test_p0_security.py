"""P0 controls: environments, CORS/headers, route authorisation, OTP, secrets."""
import base64
import importlib
import os

import pytest

from engine import settings


# ============================================================================
# P0.1 — environments and the production safety gate (finding F1)
# ============================================================================
class TestEnvironments:
    def _reload(self, **env):
        for k, v in env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        importlib.reload(settings)
        return settings

    def teardown_method(self):
        for k in ("SIMSHIELD_ENV", "SIMSHIELD_DEMO_REVEAL_OTP", "SIMSHIELD_DEBUG",
                  "SIMSHIELD_ENABLE_DEMO_ENDPOINTS", "SIMSHIELD_HTTPS",
                  "SIMSHIELD_CORS_ORIGINS"):
            os.environ.pop(k, None)
        os.environ["SIMSHIELD_ENV"] = "development"
        os.environ["SIMSHIELD_DEMO_REVEAL_OTP"] = "true"
        os.environ["SIMSHIELD_ENABLE_DEMO_ENDPOINTS"] = "true"
        importlib.reload(settings)

    def test_debug_is_off_by_default(self):
        s = self._reload(SIMSHIELD_ENV="development", SIMSHIELD_DEBUG=None)
        assert s.debug_enabled() is False

    def test_debug_impossible_in_production(self):
        s = self._reload(SIMSHIELD_ENV="production", SIMSHIELD_DEBUG="true")
        assert s.debug_enabled() is False

    def test_production_refuses_otp_reveal(self):
        s = self._reload(SIMSHIELD_ENV="production", SIMSHIELD_DEMO_REVEAL_OTP="true")
        assert any("DEMO_REVEAL_OTP" in p for p in s.production_problems())
        with pytest.raises(s.InsecureConfiguration):
            s.assert_safe_for_production()

    def test_production_refuses_demo_endpoints(self):
        s = self._reload(SIMSHIELD_ENV="production",
                         SIMSHIELD_ENABLE_DEMO_ENDPOINTS="true")
        assert any("DEMO_ENDPOINTS" in p for p in s.production_problems())

    def test_production_refuses_generated_keys(self):
        s = self._reload(SIMSHIELD_ENV="production", SIMSHIELD_DEMO_REVEAL_OTP=None,
                         SIMSHIELD_ENABLE_DEMO_ENDPOINTS=None)
        os.environ.pop("SIMSHIELD_AES_KEY", None)
        importlib.reload(settings)
        assert any("SIMSHIELD_AES_KEY" in p for p in settings.production_problems())
        os.environ["SIMSHIELD_AES_KEY"] = base64.b64encode(b"\x11" * 32).decode()

    def test_production_refuses_wildcard_cors(self):
        s = self._reload(SIMSHIELD_ENV="production", SIMSHIELD_CORS_ORIGINS="*",
                         SIMSHIELD_DEMO_REVEAL_OTP=None,
                         SIMSHIELD_ENABLE_DEMO_ENDPOINTS=None)
        assert any("Wildcard CORS" in p for p in s.production_problems())

    def test_production_refuses_plain_http_origin(self):
        s = self._reload(SIMSHIELD_ENV="production",
                         SIMSHIELD_CORS_ORIGINS="http://evil.example",
                         SIMSHIELD_DEMO_REVEAL_OTP=None,
                         SIMSHIELD_ENABLE_DEMO_ENDPOINTS=None)
        assert any("https://" in p for p in s.production_problems())

    def test_production_requires_https(self):
        s = self._reload(SIMSHIELD_ENV="production", SIMSHIELD_HTTPS="false",
                         SIMSHIELD_DEMO_REVEAL_OTP=None,
                         SIMSHIELD_ENABLE_DEMO_ENDPOINTS=None)
        assert any("SIMSHIELD_HTTPS" in p for p in s.production_problems())

    def test_otp_reveal_never_enabled_in_production(self):
        s = self._reload(SIMSHIELD_ENV="production", SIMSHIELD_DEMO_REVEAL_OTP="true")
        assert s.reveal_otp_enabled() is False

    def test_demo_endpoints_off_in_production(self):
        s = self._reload(SIMSHIELD_ENV="production",
                         SIMSHIELD_ENABLE_DEMO_ENDPOINTS="true")
        assert s.demo_endpoints_enabled() is False


# ============================================================================
# P0.2 — CORS allowlist and security headers (findings F2, F3)
# ============================================================================
class TestSecurityHeaders:
    def test_all_headers_present(self, client):
        r = client.get("/api/health")
        h = r.headers
        assert "default-src 'self'" in h["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
        assert "object-src 'none'" in h["Content-Security-Policy"]
        assert h["X-Content-Type-Options"] == "nosniff"
        assert h["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert "geolocation=(self)" in h["Permissions-Policy"]
        assert "camera=()" in h["Permissions-Policy"]
        assert h["X-Frame-Options"] == "DENY"

    def test_csp_script_src_is_self_only(self, client):
        """
        All page logic lives in external same-origin files, so the policy is
        `script-src 'self'` — no nonce, no 'unsafe-inline', no 'unsafe-eval'.
        (The earlier nonce-based policy advertised a nonce that no <script> tag
        carried, which would have blocked every script in a real browser. See
        test_p0_corrections.py for the tests that verify the served HTML.)
        """
        csp = client.get("/api/health").headers["Content-Security-Policy"]
        script = [d.strip() for d in csp.split(";")
                  if d.strip().startswith("script-src")][0]
        assert script == "script-src 'self'", script
        for unsafe in ("unsafe-inline", "unsafe-eval", "http:", "*"):
            assert unsafe not in script

    def test_csp_is_stable_across_requests(self, client):
        a = client.get("/api/health").headers["Content-Security-Policy"]
        b = client.get("/api/health").headers["Content-Security-Policy"]
        assert a == b, "policy must not vary per request now that it is static"

    def test_unknown_origin_gets_no_cors_grant(self, client):
        r = client.get("/api/health", headers={"Origin": "https://evil.example"})
        assert "Access-Control-Allow-Origin" not in r.headers

    def test_hsts_absent_without_https(self, client):
        assert "Strict-Transport-Security" not in client.get("/api/health").headers

    def test_oversized_body_rejected(self, client):
        # 512 KB against a 256 KB cap
        r = client.post("/api/auth/login", data="x" * (512 * 1024),
                        content_type="application/json")
        assert r.status_code == 413


# ============================================================================
# P0.3 — authorisation on sensitive routes
# ============================================================================
class TestRouteAuthorisation:
    @pytest.mark.parametrize("method,path", [
        ("get", "/api/operator/sim-location?user_id=sita_swapped"),
        ("get", "/api/operator/sim-swap-check?user_id=sita_swapped"),
        ("get", "/api/study/aggregate"),
        ("get", "/api/study/export.csv"),
        ("get", "/api/study/export-feedback.csv"),
        ("post", "/api/retention/enforce"),
        ("post", "/api/audit/checkpoint"),
        ("get", "/api/me/dashboard"),
        ("get", "/api/admin/overview"),
    ])
    def test_unauthenticated_is_rejected(self, client, method, path):
        r = getattr(client, method)(path)
        assert r.status_code in (401, 403), \
            f"{path} returned {r.status_code} to an anonymous caller"

    def test_retention_is_not_reachable_by_a_normal_user(self, client, signed_in):
        _, headers = signed_in()
        r = client.post("/api/retention/enforce", headers=headers)
        assert r.status_code == 403

    def test_study_export_denied_to_normal_user(self, client, signed_in):
        _, headers = signed_in()
        assert client.get("/api/study/export.csv", headers=headers).status_code == 403

    def test_study_export_allowed_for_researcher(self, client, signed_in):
        _, headers = signed_in(role="researcher")
        assert client.get("/api/study/export.csv", headers=headers).status_code == 200

    def test_admin_can_enforce_retention(self, client, signed_in):
        _, headers = signed_in(role="admin")
        assert client.post("/api/retention/enforce", headers=headers).status_code == 200

    def test_user_cannot_read_another_subscribers_sim_location(self, client, signed_in):
        # signed in without a linked profile -> may not query anyone's SIM
        _, headers = signed_in()
        r = client.get("/api/operator/sim-location?user_id=sita_swapped",
                       headers=headers)
        assert r.status_code == 403

    # NOTE: these use `aarav_safe`, not a compromised profile. Linking a test
    # account to `sita_swapped` makes the pre-OTP risk check correctly BLOCK the
    # sign-in — the control doing its job, which would mask what we are testing.
    def test_owner_can_read_own_sim_location(self, client, signed_in):
        _, headers = signed_in(profile_id="aarav_safe")
        r = client.get("/api/operator/sim-location"
                       "?user_id=aarav_safe&lat=27.7154&lon=85.3123",
                       headers=headers)
        assert r.status_code == 200
        body = r.get_json()
        assert body["simulated"] is True
        # the response is coarsened — no raw coordinates are returned
        assert "lat" not in body and "lon" not in body

    def test_operator_endpoint_rejects_invalid_coordinates(self, client, signed_in):
        _, headers = signed_in(profile_id="aarav_safe")
        r = client.get("/api/operator/sim-location"
                       "?user_id=aarav_safe&lat=999&lon=0", headers=headers)
        assert r.status_code == 400

    def test_sensitive_access_is_audited(self, client, signed_in):
        from engine import db
        user, headers = signed_in(profile_id="aarav_safe")
        client.get("/api/operator/sim-location?user_id=aarav_safe", headers=headers)
        rows = db.query_all(
            "SELECT meta FROM activity_log WHERE user_id = ? AND action = ?",
            (user["id"], "sensitive_access"))
        assert any("operator.sim_location" in r["meta"] for r in rows)


# ============================================================================
# P0.4 — OTP handling (finding F7)
# ============================================================================
class TestOtp:
    def test_login_otp_is_bound_to_its_challenge(self, client, user_factory):
        user, password = user_factory()
        r = client.post("/api/auth/login",
                        json={"email": user["email"], "password": password,
                              "fingerprint": "fp-a"})
        body = r.get_json()
        code = body["delivery"]["demo"]["otp"]
        # correct code, but no challenge -> refused
        r2 = client.post("/api/auth/verify-otp",
                         json={"email": user["email"], "code": code,
                               "fingerprint": "fp-a"})
        assert r2.status_code == 401

    def test_otp_rejected_from_a_different_device(self, client, user_factory):
        user, password = user_factory()
        body = client.post("/api/auth/login",
                           json={"email": user["email"], "password": password,
                                 "fingerprint": "fp-legit"}).get_json()
        r = client.post("/api/auth/verify-otp",
                        json={"email": user["email"],
                              "code": body["delivery"]["demo"]["otp"],
                              "challenge": body["challenge"],
                              "fingerprint": "fp-attacker"})
        assert r.status_code == 401

    def test_challenge_is_single_use(self, client, user_factory):
        user, password = user_factory()
        body = client.post("/api/auth/login",
                           json={"email": user["email"], "password": password,
                                 "fingerprint": "fp-x"}).get_json()
        args = {"email": user["email"], "code": body["delivery"]["demo"]["otp"],
                "challenge": body["challenge"], "fingerprint": "fp-x"}
        assert client.post("/api/auth/verify-otp", json=args).status_code == 200
        assert client.post("/api/auth/verify-otp", json=args).status_code == 401

    def test_otp_absent_from_response_when_reveal_disabled(self, client,
                                                           user_factory, monkeypatch):
        from engine import notifier
        monkeypatch.setattr(notifier.settings, "reveal_otp_enabled", lambda: False)
        user, password = user_factory()
        body = client.post("/api/auth/login",
                           json={"email": user["email"], "password": password,
                                 "fingerprint": "fp"}).get_json()
        assert "demo" not in (body.get("delivery") or {})

    def test_reset_does_not_enumerate_accounts(self, client, user_factory,
                                               monkeypatch):
        from engine import settings as s
        monkeypatch.setattr(s, "reveal_otp_enabled", lambda: False)
        import routes.auth_routes as ar
        monkeypatch.setattr(ar.settings, "reveal_otp_enabled", lambda: False)
        user, _ = user_factory()
        known = client.post("/api/auth/reset/request", json={"email": user["email"]})
        unknown = client.post("/api/auth/reset/request",
                              json={"email": "nobody@example.np"})
        assert known.status_code == unknown.status_code == 200
        assert known.get_json() == unknown.get_json()

    def test_otp_flows_are_rate_limited(self, client, user_factory):
        from engine import ratelimit
        ratelimit.reset()
        user, _ = user_factory()
        codes = [client.post("/api/auth/reset/request",
                             json={"email": user["email"]}).status_code
                 for _ in range(8)]
        assert 429 in codes, "reset must be rate limited"
        ratelimit.reset()

    def test_unfreeze_otp_is_rate_limited(self, client, signed_in):
        from engine import ratelimit
        ratelimit.reset()
        _, headers = signed_in()
        codes = [client.post("/api/me/unfreeze/request", headers=headers).status_code
                 for _ in range(8)]
        assert 429 in codes
        ratelimit.reset()


# ============================================================================
# P0.5 — secrets, crypto, pseudonymisation (findings F8-F11)
# ============================================================================
class TestSecretsAndCrypto:
    def test_gitignore_covers_every_sensitive_artefact(self):
        root = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        text = open(os.path.join(root, ".gitignore"), encoding="utf-8").read()
        for pattern in ("secret.key", "*.db", "*.log", "study/", ".env"):
            assert pattern in text, f"{pattern} must be git-ignored"

    def test_env_example_exists_and_holds_no_real_secret(self):
        root = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        text = open(os.path.join(root, ".env.example"), encoding="utf-8").read()
        assert "SIMSHIELD_AES_KEY=" in text
        assert "SIMSHIELD_AES_KEY=\n" in text or "SIMSHIELD_AES_KEY=" in text
        # the template must not ship a usable key
        for line in text.splitlines():
            if line.startswith("SIMSHIELD_AES_KEY="):
                assert line.strip() == "SIMSHIELD_AES_KEY="

    def test_public_default_salt_is_gone(self):
        from engine.config_loader import load_compliance
        assert "default_salt" not in load_compliance()["privacy"]

    def test_encrypt_roundtrip(self):
        from engine import crypto
        token = crypto.encrypt("+977-9800000000")
        assert token.startswith("gcm:")
        assert "9800000000" not in token
        assert crypto.decrypt(token) == "+977-9800000000"

    def test_encryption_is_nondeterministic(self):
        from engine import crypto
        assert crypto.encrypt("same") != crypto.encrypt("same")

    def test_never_writes_plaintext_pii(self):
        from engine import crypto
        assert not crypto.encrypt("secret-value").startswith("plain:")

    def test_legacy_plain_values_are_not_returned(self):
        from engine import crypto
        assert crypto.decrypt("plain:leaked@example.np") is None

    def test_pseudonym_is_keyed_and_long_enough(self):
        from engine import privacy
        p = privacy.hash_id("+977-9800000000")
        assert p.startswith("hmac-sha256:")
        assert len(p.split(":")[1]) == 32          # 128 bits

    def test_pseudonym_changes_with_the_secret(self, monkeypatch):
        from engine import privacy, settings as s
        a = privacy.hash_id("subject")
        monkeypatch.setattr(s, "pseudonym_secret", lambda: "a-different-secret" * 3)
        assert privacy.hash_id("subject") != a

    def test_pseudonym_is_stable_within_a_deployment(self):
        from engine import privacy
        assert privacy.hash_id("x") == privacy.hash_id("x")

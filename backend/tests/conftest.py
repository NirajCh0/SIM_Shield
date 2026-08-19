"""
Shared pytest fixtures.

Every test runs against a THROWAWAY database and throwaway data directories, so
the suite can never touch the real demo database, the consented study responses
or the audit log. Secrets are pinned to fixed test values so cryptographic
behaviour is deterministic.
"""
import base64
import os
import sys
import tempfile

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

# Must be set before any engine module is imported.
os.environ.setdefault("SIMSHIELD_ENV", "development")
os.environ["SIMSHIELD_AES_KEY"] = base64.b64encode(b"\x11" * 32).decode()
os.environ["SIMSHIELD_PSEUDONYM_SECRET"] = "test-pseudonym-secret-" + "x" * 32
os.environ["SIMSHIELD_SECRET_KEY"] = "test-flask-secret-" + "y" * 32
os.environ["SIMSHIELD_DEMO_REVEAL_OTP"] = "true"
os.environ["SIMSHIELD_ENABLE_DEMO_ENDPOINTS"] = "true"


@pytest.fixture(scope="session")
def tmp_data(tmp_path_factory):
    """Redirect the database and all data directories into a temp folder."""
    root = tmp_path_factory.mktemp("simshield_data")
    from engine import compliance, db, study
    db.DB_PATH = str(root / "test.db")
    study.STUDY_DIR = str(root / "study")
    study.FEEDBACK_DIR = str(root / "study_feedback")
    os.makedirs(study.STUDY_DIR, exist_ok=True)
    os.makedirs(study.FEEDBACK_DIR, exist_ok=True)
    db.init_db()
    return root


@pytest.fixture(scope="session")
def app(tmp_data):
    import app as appmod
    appmod.app.config.update(TESTING=True)
    return appmod.app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def user_factory(tmp_data):
    """Create a fresh subscriber and return (user_row, plaintext_password)."""
    from engine import auth
    counter = {"n": 0}

    def make(role="user", **kw):
        counter["n"] += 1
        email = kw.pop("email", f"u{counter['n']}_{os.urandom(3).hex()}@example.np")
        password = kw.pop("password", "TestPass!2345")
        user = auth.register(email=email, password=password,
                             display_name=kw.pop("display_name", "Test User"),
                             phone=kw.pop("phone", "+977-9800000000"),
                             role=role, **kw)
        return user, password
    return make


def csrf_from_jar(client) -> str:
    """
    Read the CSRF token the way a browser does — from the cookie jar — because
    it is deliberately NOT returned in any JSON body. Werkzeug's cookie API
    changed across versions, so both spellings are handled.
    """
    from routes.common import CSRF_COOKIE
    jar = client._cookies if hasattr(client, "_cookies") else {}
    for key, morsel in jar.items():
        name = key[-1] if isinstance(key, tuple) else key
        if name == CSRF_COOKIE:
            return morsel.value if hasattr(morsel, "value") else str(morsel)
    got = client.get_cookie(CSRF_COOKIE) if hasattr(client, "get_cookie") else None
    return getattr(got, "value", got) or ""


@pytest.fixture()
def signed_in(client, user_factory):
    """
    Sign a user in through the real 2FA flow and return (user, csrf_headers).

    The session cookie is held by the test client automatically. The CSRF token
    is read from the cookie jar — asserting it is absent from the response body
    is the job of test_login_response_leaks_no_tokens.
    """
    def _login(role="user", **kw):
        user, password = user_factory(role=role, **kw)
        r = client.post("/api/auth/login",
                        json={"email": user["email"], "password": password,
                              "fingerprint": "fp-test"})
        body = r.get_json()
        assert r.status_code == 200, body
        code = body["delivery"]["demo"]["otp"]
        r2 = client.post("/api/auth/verify-otp",
                         json={"email": user["email"], "code": code,
                               "challenge": body["challenge"],
                               "fingerprint": "fp-test"})
        assert r2.status_code == 200, r2.get_json()
        return user, {"X-CSRF-Token": csrf_from_jar(client)}
    return _login

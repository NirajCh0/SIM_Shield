"""
Scope boundaries: SIMShield is a SIM-swap detection and awareness tool, not a
banking app.

WHY THIS FILE EXISTS
The project drifted into presenting itself as a small bank — a savings-account
number, a merchant field, quick-spend presets, "Send money", a transfer history
and an explainer of four transaction-scoring rules. None of that was the
research contribution, and all of it invited a reader to evaluate SIMShield as
payments software: settlement, double-entry, PCI-DSS, floating-point money.

The one genuinely SIM-swap-shaped control in that area survives: the cooling-off
hold applied after a SIM change, released only through a channel the attacker
does not hold. These tests keep the boundary where it now is — the banking
presentation cannot creep back without failing the suite, and the containment
control cannot be deleted without failing it either.
"""
import os
import re

import pytest

from engine import db, transactions
from engine.config_loader import backend_path, load_config

FRONTEND = os.path.abspath(
    os.path.join(backend_path("x"), "..", "..", "frontend"))


def _read(name: str) -> str:
    with open(os.path.join(FRONTEND, name), encoding="utf-8") as f:
        return f.read()

def _read_root(name: str) -> str:
    """A file at the repository root (one level above backend/)."""
    with open(os.path.join(backend_path(""), os.pardir, name), encoding="utf-8") as f:
        return f.read()


def _read_backend(rel: str) -> str:
    with open(backend_path(*rel.split("/")), encoding="utf-8") as f:
        return f.read()



# =============================================================================
# The page does not present as a bank
# =============================================================================
class TestExposurePagePresentation:

    @pytest.fixture(scope="class")
    def page(self):
        return _read("money.html")

    @pytest.mark.parametrize("phrase", [
        "Send money", "Savings", "savings account", "Recent transfers",
        "Bhatbhateni", "Available balance", "How a transfer is judged",
    ])
    def test_banking_product_language_is_gone(self, phrase, page):
        assert phrase not in page, (
            f"{phrase!r} presents SIMShield as a banking product — the scope "
            "decision was to show exposure and containment, not payments")

    def test_the_page_states_plainly_that_this_is_not_a_bank(self, page):
        assert "not a bank" in page.lower()
        assert "synthetic" in page.lower()

    def test_the_balance_is_labelled_as_funds_at_risk(self, page):
        """The number is the stake a SIM swap puts at risk, not an account."""
        assert "Simulated funds at risk" in page

    def test_the_cooling_off_hold_is_the_headline_control(self, page):
        assert "Cooling-off hold after a SIM change" in page
        assert "held" in page.lower()

    def test_the_page_explains_why_release_uses_a_different_channel(self, page):
        """The whole point of the hold is the out-of-band release."""
        text = page.lower()
        assert "email" in text
        assert "does not control" in text or "cannot read" in text

    def test_no_merchant_field_is_offered(self, page):
        assert 'id="txn-merchant"' not in page
        assert 'id="preset-row"' not in page

    def test_the_amount_input_accepts_whole_rupees_only(self, page):
        match = re.search(r'<input[^>]*id="txn-amount"[^>]*>', page)
        assert match, "the test-payment input is missing"
        assert 'step="1"' in match.group(0)

    def test_the_navigation_no_longer_says_money(self):
        shell = _read("shell.js")
        assert '"Exposure"' in shell
        assert 'label: "Money"' not in shell

    def test_the_installed_app_shortcut_is_not_a_payments_feature(self):
        """
        The PWA manifest advertises shortcuts on the home screen. One still said
        "Send money", so the banking framing survived the page rewrite in the
        one place a user sees before opening the app at all.
        """
        import json
        manifest = json.loads(_read("manifest.webmanifest"))
        for shortcut in manifest.get("shortcuts", []):
            label = f"{shortcut.get('name','')} {shortcut.get('short_name','')}"
            assert "Send money" not in label, "the app shortcut still offers payments"
            assert "money" not in label.lower() or "risk" in label.lower()


# =============================================================================
# The API stops collecting what it does not need
# =============================================================================
class TestDataMinimisation:

    def test_the_api_ignores_a_merchant_even_if_one_is_sent(self, client, signed_in):
        """
        Knowing what a subscriber buys is not needed to detect a SIM swap, so a
        client cannot make SIMShield record it — not even by sending it.
        """
        user, headers = signed_in(profile_id="aarav_safe")
        r = client.post("/api/me/transactions",
                        json={"amount": 1200, "merchant": "Bhatbhateni Supermarket",
                              "category": "groceries"},
                        headers=headers)
        assert r.status_code in (200, 403), r.get_json()
        row = db.query_one(
            "SELECT merchant, category FROM transactions WHERE user_id = ? "
            "ORDER BY id DESC LIMIT 1", (user["id"],))
        if row:                       # a refused attempt is not stored at all
            assert not row["merchant"], "a merchant was stored despite not being asked for"
            assert not row["category"]

    def test_fractional_amounts_are_refused(self, client, signed_in):
        """
        Whole rupees only — this is what makes the REAL balance arithmetic exact
        rather than merely usually-exact.
        """
        _user, headers = signed_in(profile_id="aarav_safe")
        r = client.post("/api/me/transactions", json={"amount": 12.34},
                        headers=headers)
        assert r.status_code == 400

    def test_a_fractional_amount_is_not_silently_truncated(self, client, signed_in):
        """
        The defect behind the previous test: `int(12.34)` gave 12, so a request
        for one amount was executed as another with no error. Rejecting a
        malformed number is right; quietly rounding a payment is not.
        """
        user, headers = signed_in(profile_id="aarav_safe")
        before = db.query_one("SELECT balance FROM users WHERE id = ?",
                              (user["id"],))["balance"]
        client.post("/api/me/transactions", json={"amount": 12.34}, headers=headers)
        after = db.query_one("SELECT balance FROM users WHERE id = ?",
                             (user["id"],))["balance"]
        assert after == before, "a rejected amount still moved the balance"

    def test_the_validator_rejects_fractions_everywhere_not_just_here(self):
        """This was a general defect in `Validator.number(integer=True)`."""
        from engine.validation import ValidationError, Validator
        v = Validator({"n": 7.5})
        v.number("n", integer=True)
        with pytest.raises(ValidationError):
            v.done()
        assert Validator({"n": 7.0}).number("n", integer=True).done()["n"] == 7
        assert Validator({"n": "7"}).number("n", integer=True).done()["n"] == 7

    def test_repeated_debits_leave_the_balance_exact(self, user_factory):
        """
        The concrete float bug this closes: subtracting 0.1 a thousand times
        from 150000 lands on 149899.99999999418. With integral amounts every
        value stays well under 2^53, where IEEE-754 subtraction is exact.
        """
        user, _pw = user_factory(profile_id="aarav_safe")
        start = db.query_one("SELECT balance FROM users WHERE id = ?",
                             (user["id"],))["balance"]
        spent = 0
        for amount in (137, 2519, 44, 9803, 7):
            fresh = db.query_one("SELECT * FROM users WHERE id = ?", (user["id"],))
            result = transactions.assess(fresh, float(amount))
            if result.get("accepted") is not False and result["status"] == "posted":
                spent += amount
        end = db.query_one("SELECT balance FROM users WHERE id = ?",
                           (user["id"],))["balance"]
        assert end == start - spent, f"balance drifted: {end!r} vs {start - spent!r}"
        assert end == int(end), "balance is no longer a whole number of rupees"


# =============================================================================
# The containment control itself must not be deleted
# =============================================================================
class TestContainmentControlSurvives:

    def test_the_sim_change_rule_still_exists_and_is_weighted(self):
        src = _read.__module__ and open(
            backend_path("engine", "transactions.py"), encoding="utf-8").read()
        assert "_recent_sim_change" in src
        assert "sim_change_lookback_days" in src

    def test_a_payment_after_a_sim_change_is_held_not_allowed(self, user_factory):
        """
        The single most important behaviour on this page: after a SIM change a
        large payment is neither refused nor allowed — it is HELD, pending an
        out-of-band release.
        """
        user, _pw = user_factory(profile_id="aarav_safe")
        cfg = load_config()["transactions"]
        db.execute(
            "INSERT INTO sim_events (user_id, event_type, operator, risk_score, "
            "details, occurred_at) VALUES (?,'sim_swap','NTC',92.0,'test',?)",
            (user["id"], db.now()))
        fresh = db.query_one("SELECT * FROM users WHERE id = ?", (user["id"],))
        result = transactions.assess(fresh, float(cfg["hold_threshold_amount"] + 5000))
        assert result["status"] == "held", result
        assert any("SIM" in r for r in result["reasons"])

    def test_releasing_a_hold_requires_a_code(self, client, signed_in, user_factory):
        user, headers = signed_in(profile_id="aarav_safe")
        db.execute(
            "INSERT INTO sim_events (user_id, event_type, operator, risk_score, "
            "details, occurred_at) VALUES (?,'sim_swap','NTC',92.0,'test',?)",
            (user["id"], db.now()))
        cfg = load_config()["transactions"]
        r = client.post("/api/me/transactions",
                        json={"amount": cfg["hold_threshold_amount"] + 5000},
                        headers=headers)
        body = r.get_json()
        assert body["status"] == "held", body
        # Confirming without ever requesting a code must fail.
        bad = client.post(f"/api/me/transactions/{body['id']}/release/confirm",
                          json={"code": "000000"}, headers=headers)
        assert bad.status_code >= 400


# =============================================================================
# The public config endpoint is an allowlist
# =============================================================================
class TestPublicConfig:

    def test_it_exposes_only_what_the_ui_needs_to_describe_itself(self, client):
        body = client.get("/api/config/public").get_json()
        assert set(body) == {"sim_change_lookback_days", "hold_threshold_amount",
                             "currency", "simulated"}

    def test_it_does_not_leak_detection_thresholds(self, client):
        """
        An attacker who knows the exact scoring thresholds can tune an attack to
        sit just underneath them. Nothing from the detection config belongs here.
        """
        body = client.get("/api/config/public").get_json()
        blob = str(body)
        for leaked in ("allow_max", "monitor_max", "verify_max", "zscore",
                       "flag_threshold", "fusion", "burst_count"):
            assert leaked not in blob

    def test_the_page_reads_the_window_from_config_rather_than_hardcoding_it(self):
        """Copy that contradicts the running system is the over-claim problem."""
        src = _read("money.page.js")
        assert "/api/config/public" in src
        assert 'g("lookback-days")' in src
        page = _read("money.html")
        assert 'id="lookback-days"' in page


# =============================================================================
# First-run experience: a fresh clone must be usable
# =============================================================================
class TestFirstRunWorks:
    """
    A downloaded copy could not be signed into. Two bugs combined:

      1. `.env.example` — which the README's first step tells you to copy to
         `.env` — set `SIMSHIELD_DEMO_REVEAL_OTP=false`. With no SMTP server
         configured, the one-time code then goes nowhere at all.
      2. Nothing ever read `.env`. `python-dotenv` was not a dependency and no
         code called `load_dotenv()`, so every value a user set was silently
         ignored.

    The two cancelled out, which is why login still worked here — a latent trap,
    because fixing (2) alone would have locked every user out. Both are fixed;
    these tests keep them fixed.
    """

    def test_env_example_does_not_disable_the_only_way_to_get_a_code(self):
        env = _read_root(".env.example")
        for line in env.splitlines():
            if line.strip().startswith("SIMSHIELD_DEMO_REVEAL_OTP="):
                value = line.split("=", 1)[1].strip().lower()
                assert value == "true", (
                    "the sample .env disables OTP reveal; with no SMTP configured "
                    "that makes signing in impossible on a fresh clone")
                return
        pytest.fail("SIMSHIELD_DEMO_REVEAL_OTP is missing from .env.example")

    def test_dotenv_is_actually_loaded(self):
        """Documentation promised a .env mechanism that did not exist."""
        from engine import settings
        assert hasattr(settings, "_load_dotenv")
        src = _read_backend("engine/settings.py")
        assert "_load_dotenv()" in src, "the loader is defined but never called"
        assert "override=False" in src, (
            "a stale .env must never override a real environment variable")

    def test_dotenv_is_declared_as_a_dependency(self):
        assert "python-dotenv" in _read_backend("requirements.txt")

    def test_development_reveals_the_code_so_login_is_possible(self, client,
                                                               user_factory):
        """The end-to-end property: a new user can actually get in."""
        user, password = user_factory(profile_id="aarav_safe")
        r = client.post("/api/auth/login",
                        json={"email": user["email"], "password": password,
                              "fingerprint": "fp-firstrun"})
        body = r.get_json()
        otp = ((body.get("delivery") or {}).get("demo") or {}).get("otp")
        assert otp, ("no code was revealed and no mail server exists — a user "
                     "following the README could never sign in")
        assert client.post("/api/auth/verify-otp",
                           json={"email": user["email"], "code": otp,
                                 "challenge": body["challenge"],
                                 "fingerprint": "fp-firstrun"}).status_code == 200

    def test_the_readme_says_where_the_code_appears(self):
        readme = _read_root("README.md")
        assert "No email is sent" in readme
        assert "Demo outbox" in readme

    def test_the_readme_does_not_print_a_real_looking_sample_code(self):
        """
        The example banner read 'Your code is 165077', which a reader took for
        a constant. Codes are random per sign-in; the sample must look like a
        placeholder.
        """
        readme = _read_root("README.md")
        assert "165077" not in readme
        assert "######" in readme

    def test_missing_evaluation_report_is_reported_not_a_404(self, client,
                                                             monkeypatch):
        """
        On a fresh clone the evaluation report does not exist — it is generated
        output and git-ignored. The endpoint used to 404, so /metrics rendered
        an empty page with the reason visible only in the browser console.
        A first-run state is not an error.
        """
        import app as appmod
        monkeypatch.setattr(appmod.os.path, "exists", lambda p: False)
        r = client.get("/api/evaluation")
        assert r.status_code == 200, "a missing report is a first-run state, not an error"
        body = r.get_json()
        assert body["available"] is False
        assert "evaluate.py" in body["how_to_fix"]

    def test_the_metrics_page_handles_an_absent_report(self):
        """The page must render the explanation, not just fall through."""
        src = _read("metrics.page.js")
        assert "rep.available === false" in src
        assert "how_to_fix" in src

    def test_the_figure_generator_explains_missing_reports(self):
        """It crashed with a FileNotFoundError traceback on a clean clone."""
        src = _read_backend("make_thesis_figures.py")
        assert "PRODUCED_BY" in src
        assert "SystemExit" in src
        assert "generated, not committed" in src

    def test_the_figure_generator_has_no_hardcoded_absolute_path(self):
        """An absolute path to one developer's Desktop was committed."""
        src = _read_backend("make_thesis_figures.py")
        assert "C:/Users" not in src and "c:/Users" not in src
        assert "os.path.dirname(os.path.abspath(__file__))" in src

"""
Tests for fraud-analyst case management with reason codes (improvement #2).

The property under test throughout: **an analyst's decision cannot be recorded
in a form nobody can review.** Every test below is a way that could otherwise
fail — an outcome with no code, an outcome that contradicts its code, a
false-positive claim with no evidence, or an analyst quietly closing a case
about their own account.
"""
import json

import pytest

from engine import cases, compliance, db
from engine.config_loader import load_reason_codes


@pytest.fixture()
def analyst(user_factory):
    user, _pw = user_factory(role="admin")
    return user


@pytest.fixture()
def subject(user_factory):
    user, _pw = user_factory(profile_id="aarav_safe")
    return user


@pytest.fixture()
def a_case(subject):
    return cases.open_case(subject["id"], "Test case", severity="high",
                           decision="BLOCK", risk_score=91.0)


# =============================================================================
# The taxonomy itself
# =============================================================================
class TestTaxonomy:

    def test_every_code_declares_an_outcome_that_exists(self):
        spec = load_reason_codes()
        outcomes = set(spec["outcomes"])
        for entry in spec["codes"]:
            assert entry["outcome"] in outcomes, entry["code"]

    def test_every_code_has_guidance_and_a_category(self):
        """A code an analyst cannot interpret consistently is not a taxonomy."""
        for entry in load_reason_codes()["codes"]:
            assert entry.get("guidance"), entry["code"]
            assert entry.get("category"), entry["code"]

    def test_codes_are_unique(self):
        codes = [c["code"] for c in load_reason_codes()["codes"]]
        assert len(codes) == len(set(codes))

    def test_only_false_positive_outcomes_count_against_the_detector(self):
        """
        `counts_as_false_positive` must never be set on a code whose outcome is
        anything other than false_positive — otherwise the measured FPR silently
        includes confirmed fraud or inconclusive cases.
        """
        for entry in load_reason_codes()["codes"]:
            if entry.get("counts_as_false_positive"):
                assert entry["outcome"] == "false_positive", entry["code"]

    def test_inconclusive_never_counts_as_a_false_positive(self):
        for entry in load_reason_codes()["codes"]:
            if entry["outcome"] in ("inconclusive", "duplicate"):
                assert not entry.get("counts_as_false_positive"), entry["code"]

    def test_taxonomy_is_exposed_to_the_analyst_ui(self, client, signed_in):
        _user, headers = signed_in(role="admin")
        body = client.get("/api/admin/reason-codes").get_json()
        assert body["version"]
        assert len(body["codes"]) == len(cases.valid_codes())


# =============================================================================
# Resolution requires a code, and the code determines the outcome
# =============================================================================
class TestResolutionIsCoded:

    def test_a_case_cannot_be_resolved_through_the_status_route(self, a_case, analyst):
        """
        The gap this improvement closes: previously 'resolved' was just another
        status value, so a case could be closed with no recorded justification.
        """
        with pytest.raises(ValueError, match="reason code"):
            cases.set_status(a_case["id"], "resolved", analyst["id"])

    def test_status_endpoint_refuses_resolved(self, client, signed_in, a_case):
        _user, headers = signed_in(role="admin")
        r = client.post(f"/api/admin/cases/{a_case['id']}/status",
                        json={"status": "resolved"}, headers=headers)
        assert r.status_code == 400

    def test_unknown_reason_code_is_refused(self, a_case, analyst):
        with pytest.raises(cases.ResolutionError, match="Unknown reason code"):
            cases.resolve(a_case["id"], "NOPE99", analyst["id"], evidence="x")

    def test_outcome_is_derived_from_the_code_not_supplied(self, a_case, analyst):
        """
        The client never sends an outcome. A resolution therefore cannot claim
        'false positive' while citing a confirmed-fraud reason.
        """
        resolved = cases.resolve(a_case["id"], "FR01", analyst["id"],
                                 evidence="Operator confirmed the swap.")
        assert resolved["outcome"] == "confirmed_fraud"
        assert resolved["reason_code"] == "FR01"

    def test_the_resolve_endpoint_ignores_a_client_supplied_outcome(
            self, client, signed_in, a_case):
        _user, headers = signed_in(role="admin")
        r = client.post(f"/api/admin/cases/{a_case['id']}/resolve",
                        json={"reason_code": "FR01", "outcome": "false_positive",
                              "evidence": "Operator confirmed."},
                        headers=headers)
        assert r.status_code == 200
        assert r.get_json()["outcome"] == "confirmed_fraud"

    def test_codes_requiring_evidence_are_refused_without_it(self, a_case, analyst):
        spec = cases.code_spec("FP01")
        assert spec["requires_evidence"]
        with pytest.raises(cases.ResolutionError, match="requires an evidence note"):
            cases.resolve(a_case["id"], "FP01", analyst["id"], note="trust me")

    def test_a_code_not_requiring_evidence_resolves_without_it(self, a_case, analyst):
        resolved = cases.resolve(a_case["id"], "FP05", analyst["id"])
        assert resolved["outcome"] == "false_positive"

    def test_a_resolved_case_cannot_be_resolved_again(self, a_case, analyst):
        cases.resolve(a_case["id"], "FP05", analyst["id"])
        with pytest.raises(cases.ResolutionError, match="already resolved"):
            cases.resolve(a_case["id"], "FR03", analyst["id"])


# =============================================================================
# Separation of duties
# =============================================================================
class TestSeparationOfDuties:

    def test_an_analyst_cannot_resolve_a_case_about_their_own_account(self, analyst):
        own = cases.open_case(analyst["id"], "Case about the analyst",
                              decision="BLOCK", risk_score=90.0)
        with pytest.raises(cases.ResolutionError, match="their own account"):
            cases.resolve(own["id"], "FP05", analyst["id"])

    def test_another_analyst_can_resolve_it(self, analyst, user_factory):
        other, _pw = user_factory(role="admin")
        own = cases.open_case(analyst["id"], "Case about the analyst",
                              decision="BLOCK", risk_score=90.0)
        resolved = cases.resolve(own["id"], "FP05", other["id"])
        assert resolved["status"] == "resolved"


# =============================================================================
# Audit trail for staff
# =============================================================================
class TestStaffAccountability:

    def test_resolving_writes_a_staff_action_to_the_audit_chain(
            self, tmp_data, a_case, analyst):
        log = str(tmp_data / "staff_audit.log")
        with compliance.redirect_audit(log):
            cases.resolve(a_case["id"], "FP05", analyst["id"], note="closed")
        lines = [json.loads(l) for l in open(log, encoding="utf-8") if l.strip()]
        staff = [l for l in lines if l.get("kind") == "staff_action"]
        assert staff, "no staff action was audited"
        entry = staff[-1]
        assert entry["action"] == "case_resolved"
        assert entry["meta"]["reason_code"] == "FP05"

    def test_the_analyst_is_pseudonymised_in_the_audit_log(
            self, tmp_data, a_case, analyst):
        log = str(tmp_data / "staff_pseudo.log")
        with compliance.redirect_audit(log):
            cases.resolve(a_case["id"], "FP05", analyst["id"])
        written = open(log, encoding="utf-8").read()
        assert analyst["email"] not in written
        assert str(analyst["id"]) not in json.loads(
            written.strip().splitlines()[-1])["actor"]

    def test_the_audit_chain_still_verifies_with_staff_entries(
            self, tmp_data, a_case, analyst):
        log = str(tmp_data / "staff_chain.log")
        with compliance.redirect_audit(log):
            cases.assign(a_case["id"], analyst["id"], analyst["id"])
            cases.set_status(a_case["id"], "investigating", analyst["id"])
            cases.resolve(a_case["id"], "FP05", analyst["id"])
            result = compliance.verify_audit_chain()
        assert result["intact"] is True
        assert result["entries"] >= 3


# =============================================================================
# Lifecycle and queue behaviour
# =============================================================================
class TestLifecycle:

    def test_reopening_preserves_the_previous_outcome_in_the_notes(
            self, a_case, analyst, user_factory):
        cases.resolve(a_case["id"], "FP05", analyst["id"])
        cases.reopen(a_case["id"], analyst["id"], "New evidence arrived.")
        reopened = cases.get_case(a_case["id"])
        assert reopened["status"] == "investigating"
        assert reopened["outcome"] is None
        history = json.dumps(cases.notes(a_case["id"]))
        assert "FP05" in history, "the erased outcome left no trace"

    def test_auto_open_creates_a_case_for_a_block(self, subject):
        case = cases.auto_open_for_decision(subject["id"], "BLOCK", 92.0, ["reason"])
        assert case is not None
        assert case["severity"] == "critical"
        assert case["source"] == "detector"

    def test_auto_open_ignores_allow(self, subject):
        assert cases.auto_open_for_decision(subject["id"], "ALLOW", 5.0) is None

    def test_repeated_blocks_within_an_hour_do_not_duplicate_the_case(self, subject):
        first = cases.auto_open_for_decision(subject["id"], "BLOCK", 92.0)
        second = cases.auto_open_for_decision(subject["id"], "BLOCK", 93.0)
        third = cases.auto_open_for_decision(subject["id"], "BLOCK", 94.0)
        assert first["id"] == second["id"] == third["id"]

    def test_sla_due_date_follows_severity(self, subject):
        critical = cases.open_case(subject["id"], "c", severity="critical")
        low = cases.open_case(subject["id"], "l", severity="low")
        assert critical["due_at"] < low["due_at"]

    def test_queue_stats_count_outcomes_by_code(self, subject, analyst):
        for code in ("FP05", "FR03", "FP05"):
            case = cases.open_case(subject["id"], "x", decision="VERIFY",
                                   risk_score=40.0)
            cases.resolve(case["id"], code, analyst["id"])
        stats = cases.queue_stats()
        by_code = {r["reason_code"]: r["n"] for r in stats["by_reason_code"]}
        assert by_code["FP05"] >= 2
        assert stats["median_hours_to_resolve"] is not None


# =============================================================================
# Authorisation
# =============================================================================
class TestCaseRoutesRequireAdmin:

    @pytest.mark.parametrize("path", [
        "/api/admin/cases", "/api/admin/reason-codes",
        "/api/admin/appeals", "/api/admin/monitoring", "/api/admin/feedback",
    ])
    def test_anonymous_is_refused(self, client, path):
        assert client.get(path).status_code == 401

    @pytest.mark.parametrize("path", [
        "/api/admin/cases", "/api/admin/reason-codes", "/api/admin/monitoring",
    ])
    def test_an_ordinary_subscriber_is_refused(self, client, signed_in, path):
        _user, _headers = signed_in(role="user")
        assert client.get(path).status_code == 403

    def test_resolving_requires_csrf(self, client, signed_in, a_case):
        _user, _headers = signed_in(role="admin")
        r = client.post(f"/api/admin/cases/{a_case['id']}/resolve",
                        json={"reason_code": "FP05"})     # no CSRF header
        assert r.status_code in (400, 403)

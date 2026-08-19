"""
Tests for the appeal / false-positive feedback loop (improvement #3).

Two properties matter here and both are ways the loop could quietly become
dishonest:

  1. **An appeal decision cannot contradict its reason code.** Upholding an
     appeal means the system was wrong, so it must be recorded with a code that
     counts against the detector. An analyst must not be able to soothe a
     subscriber with "upheld" while citing a code that leaves the accuracy
     figures untouched.
  2. **The measured false-positive rate refuses to be confident on thin data.**
     A percentage computed over four reviewed cases would get quoted.
"""
import pytest

from engine import appeals, cases, db, feedback


@pytest.fixture()
def analyst(user_factory):
    user, _pw = user_factory(role="admin")
    return user


@pytest.fixture()
def subject(user_factory):
    user, _pw = user_factory(profile_id="aarav_safe")
    return user


@pytest.fixture()
def clean_slate(tmp_data):
    """
    Empty the case and appeal tables before a test that asserts on GLOBAL
    aggregates.

    The test database is session-scoped, so a rate computed over "all resolved
    cases" otherwise depends on which tests ran first — the sort of order
    dependency that makes a suite pass locally and fail in CI. Safe here: this
    is a throwaway database created by `tmp_data`, never the real one.
    """
    for table in ("case_notes", "appeals", "cases"):
        db.execute(f"DELETE FROM {table}")
    return True


@pytest.fixture()
def an_appeal(subject):
    return appeals.submit(subject, "I was in Pokhara for a family wedding. "
                                   "That sign-in was me.",
                          decision="BLOCK", risk_score=88.0)


# =============================================================================
# Filing
# =============================================================================
class TestSubmission:

    def test_an_appeal_opens_a_linked_case(self, an_appeal):
        assert an_appeal["case_id"]
        case = cases.get_case(an_appeal["case_id"])
        assert case["source"] == "appeal"
        assert case["status"] == "open"

    def test_the_subscriber_statement_reaches_the_case_notes(self, an_appeal):
        bodies = " ".join(n["body"] for n in cases.notes(an_appeal["case_id"]))
        assert "family wedding" in bodies

    def test_a_too_short_statement_is_refused(self, subject):
        with pytest.raises(appeals.AppealError, match="at least a sentence"):
            appeals.submit(subject, "no", decision="BLOCK")

    def test_an_allow_decision_cannot_be_appealed(self, subject):
        """Appealing a decision that restricted nothing is not a false positive."""
        with pytest.raises(appeals.AppealError, match="did not restrict"):
            appeals.submit(subject, "I want to appeal this anyway please.",
                           decision="ALLOW")

    def test_open_appeals_are_capped_per_subscriber(self, subject):
        for i in range(appeals.MAX_OPEN_PER_USER):
            appeals.submit(subject, f"Appeal number {i}, this was genuinely me.",
                           decision="VERIFY")
        with pytest.raises(appeals.AppealError, match="awaiting review"):
            appeals.submit(subject, "One appeal too many, this was also me.",
                           decision="VERIFY")

    def test_stored_context_carries_no_raw_coordinates(self, subject):
        appeal = appeals.submit(
            subject, "This sign-in was me, I was at home in Thamel.",
            decision="BLOCK", risk_score=90.0,
            context={"current_location": {"lat": 27.7154, "lon": 85.3123},
                     "imei": "356938035643809"})
        blob = str(appeal["context"])
        assert "27.7" not in blob and "85.3" not in blob
        assert "356938035643809" not in blob

    def test_a_subscriber_can_withdraw_their_own_appeal(self, an_appeal, subject):
        result = appeals.withdraw(an_appeal["id"], subject["id"])
        assert result["status"] == "withdrawn"

    def test_a_subscriber_cannot_withdraw_someone_elses(self, an_appeal, user_factory):
        other, _pw = user_factory()
        with pytest.raises(appeals.AppealError, match="not found"):
            appeals.withdraw(an_appeal["id"], other["id"])


# =============================================================================
# Review: the decision and the code must agree
# =============================================================================
class TestReviewConsistency:

    def test_upholding_with_a_non_false_positive_code_is_refused(
            self, an_appeal, analyst):
        with pytest.raises(appeals.AppealError, match="not a false-positive code"):
            appeals.review(an_appeal["id"], analyst["id"], uphold=True,
                           reason_code="FR01", evidence="operator confirmed")

    def test_rejecting_with_a_false_positive_code_is_refused(
            self, an_appeal, analyst):
        with pytest.raises(appeals.AppealError, match="subscriber was right"):
            appeals.review(an_appeal["id"], analyst["id"], uphold=False,
                           reason_code="FP01", evidence="they travelled")

    def test_upholding_records_a_false_positive_on_the_case(self, an_appeal, analyst):
        result = appeals.review(an_appeal["id"], analyst["id"], uphold=True,
                                reason_code="FP01",
                                evidence="Boarding pass and hotel booking checked.")
        assert result["status"] == "upheld"
        case = cases.get_case(result["case_id"])
        assert case["outcome"] == "false_positive"
        assert case["reason_code"] == "FP01"
        assert case["status"] == "resolved"

    def test_rejecting_resolves_the_case_as_fraud(self, an_appeal, analyst):
        result = appeals.review(an_appeal["id"], analyst["id"], uphold=False,
                                reason_code="FR03")
        assert result["status"] == "rejected"
        assert cases.get_case(result["case_id"])["outcome"] == "confirmed_fraud"

    def test_an_analyst_cannot_review_their_own_appeal(self, analyst):
        own = appeals.submit(analyst, "This was me, I promise, let me back in.",
                             decision="BLOCK")
        with pytest.raises(appeals.AppealError, match="their own appeal"):
            appeals.review(own["id"], analyst["id"], uphold=True,
                           reason_code="FP05")

    def test_an_appeal_cannot_be_reviewed_twice(self, an_appeal, analyst):
        appeals.review(an_appeal["id"], analyst["id"], uphold=True,
                       reason_code="FP05")
        with pytest.raises(appeals.AppealError, match="already been answered"):
            appeals.review(an_appeal["id"], analyst["id"], uphold=False,
                           reason_code="FR03")

    def test_a_failed_case_resolution_rolls_the_appeal_back(self, an_appeal, analyst):
        """
        FP01 demands evidence. If the case refuses, the appeal must not be left
        marked 'upheld' with an unresolved case behind it.
        """
        with pytest.raises(appeals.AppealError, match="requires an evidence note"):
            appeals.review(an_appeal["id"], analyst["id"], uphold=True,
                           reason_code="FP01")
        assert appeals.get(an_appeal["id"])["status"] == "reviewing"
        assert cases.get_case(an_appeal["case_id"])["status"] != "resolved"


# =============================================================================
# The measured false-positive rate
# =============================================================================
class TestMeasuredFalsePositiveRate:

    def _resolve_n(self, user_factory, analyst, code: str, decision: str, n: int):
        subject, _pw = user_factory(profile_id="aarav_safe")
        for _ in range(n):
            case = cases.open_case(subject["id"], "generated", decision=decision,
                                   risk_score=70.0)
            cases.resolve(case["id"], code, analyst["id"], evidence="checked")

    def test_thin_data_reports_no_rate_at_all(self, clean_slate, analyst,
                                              user_factory):
        self._resolve_n(user_factory, analyst, "FP05", "BLOCK", 3)
        overall = feedback.measured_false_positive_rate()["overall"]
        assert overall["sufficient"] is False
        assert overall["rate"] is None
        assert "at least" in overall["note"]

    def test_a_rate_appears_once_there_are_enough_labels(self, clean_slate,
                                                         analyst, user_factory):
        self._resolve_n(user_factory, analyst, "FP05", "BLOCK",
                        feedback.MIN_REVIEWED)
        self._resolve_n(user_factory, analyst, "FR03", "BLOCK",
                        feedback.MIN_REVIEWED)
        overall = feedback.measured_false_positive_rate()["overall"]
        assert overall["sufficient"] is True
        assert overall["rate"] == pytest.approx(0.5, abs=0.05)
        low, high = overall["ci95"]
        assert 0.0 <= low < overall["rate"] < high <= 1.0

    def test_inconclusive_outcomes_are_excluded_from_the_denominator(
            self, clean_slate, analyst, user_factory):
        before = feedback.measured_false_positive_rate()
        self._resolve_n(user_factory, analyst, "IN02", "BLOCK", 10)
        after = feedback.measured_false_positive_rate()
        assert after["overall"]["total"] == before["overall"]["total"]
        assert after["excluded_inconclusive_or_duplicate"] > \
               before["excluded_inconclusive_or_duplicate"]

    def test_allow_decisions_never_enter_the_restrictive_denominator(
            self, clean_slate, analyst, user_factory):
        before = feedback.measured_false_positive_rate()["overall"]["total"]
        self._resolve_n(user_factory, analyst, "FP05", "ALLOW", 5)
        after = feedback.measured_false_positive_rate()["overall"]["total"]
        assert after == before

    def test_the_report_states_it_is_not_the_model_card_figure(self):
        caveats = " ".join(
            feedback.measured_false_positive_rate()["caveats"]).lower()
        assert "lower bound" in caveats
        assert "not comparable" in caveats

    def test_the_label_source_is_named(self):
        report = feedback.measured_false_positive_rate()
        assert "analyst" in report["label_source"]


# =============================================================================
# HTTP surface
# =============================================================================
class TestAppealRoutes:

    def test_a_subscriber_can_file_and_see_their_appeal(self, client, signed_in):
        _user, headers = signed_in(profile_id="aarav_safe")
        r = client.post("/api/me/appeals",
                        json={"statement": "That sign-in was me, I was travelling.",
                              "decision": "VERIFY", "risk_score": 45.0},
                        headers=headers)
        assert r.status_code == 201, r.get_json()
        listing = client.get("/api/me/appeals").get_json()
        assert len(listing["appeals"]) == 1
        assert listing["appeals"][0]["status"] == "submitted"

    def test_filing_requires_authentication(self, client):
        assert client.post("/api/me/appeals",
                           json={"statement": "let me in please, this was me"}
                           ).status_code == 401

    def test_filing_requires_csrf(self, client, signed_in):
        _user, _headers = signed_in()
        r = client.post("/api/me/appeals",
                        json={"statement": "That sign-in was me, I was travelling."})
        assert r.status_code in (400, 403)

    def test_a_subscriber_cannot_see_the_analyst_queue(self, client, signed_in):
        _user, _headers = signed_in(role="user")
        assert client.get("/api/admin/appeals").status_code == 403

    def test_an_analyst_reviews_through_the_api(self, client, signed_in,
                                                user_factory):
        subject, _pw = user_factory(profile_id="aarav_safe")
        appeal = appeals.submit(subject, "This was me, I was at work as usual.",
                                decision="BLOCK", risk_score=90.0)
        _admin, headers = signed_in(role="admin")
        r = client.post(f"/api/admin/appeals/{appeal['id']}/review",
                        json={"uphold": True, "reason_code": "FP01",
                              "evidence": "Employer confirmed attendance."},
                        headers=headers)
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["status"] == "upheld"

    def test_a_contradictory_review_is_rejected_by_the_api(self, client, signed_in,
                                                           user_factory):
        subject, _pw = user_factory(profile_id="aarav_safe")
        appeal = appeals.submit(subject, "This was genuinely me signing in.",
                                decision="BLOCK", risk_score=90.0)
        _admin, headers = signed_in(role="admin")
        r = client.post(f"/api/admin/appeals/{appeal['id']}/review",
                        json={"uphold": True, "reason_code": "FR01",
                              "evidence": "operator confirmed"},
                        headers=headers)
        assert r.status_code == 400
        assert "false-positive" in r.get_json()["error"]


# =============================================================================
# Retention
# =============================================================================
class TestRetention:

    def test_resolved_appeals_past_the_window_are_purged(self, subject, analyst):
        appeal = appeals.submit(subject, "An old appeal, long since answered.",
                                decision="VERIFY")
        appeals.review(appeal["id"], analyst["id"], uphold=True, reason_code="FP05")
        db.execute("UPDATE appeals SET resolved_at = datetime('now','-800 days') "
                   "WHERE id = ?", (appeal["id"],))
        removed = appeals.purge_expired()
        assert removed >= 1
        assert appeals.get(appeal["id"]) is None

    def test_the_retention_job_actually_purges_appeals_and_cases(
            self, clean_slate, subject, analyst):
        """
        `appeals.purge_expired()` existed but was never called by
        `compliance.enforce_retention()` — the policy was documented in
        compliance.yaml and enforced by nothing. A retention window that no job
        applies is a data-protection claim the system does not honour.
        """
        from engine import compliance
        appeal = appeals.submit(subject, "An old appeal, long since answered.",
                                decision="VERIFY")
        appeals.review(appeal["id"], analyst["id"], uphold=True, reason_code="FP05")
        old = "datetime('now','-900 days')"
        db.execute(f"UPDATE appeals SET resolved_at = {old} WHERE id = ?",
                   (appeal["id"],))
        db.execute(f"UPDATE cases SET resolved_at = {old} WHERE id = ?",
                   (appeal["case_id"],))

        report = compliance.enforce_retention()["database_purged"]
        assert "appeals" in report, "enforce_retention does not touch appeals at all"
        assert "cases" in report, "enforce_retention does not touch cases at all"
        assert appeals.get(appeal["id"]) is None
        assert cases.get_case(appeal["case_id"]) is None

    def test_the_retention_job_never_purges_an_open_case(self, clean_slate, subject):
        """Someone waiting for an answer must not have their case deleted."""
        from engine import compliance
        appeal = appeals.submit(subject, "Still waiting for an answer on this.",
                                decision="VERIFY")
        db.execute("UPDATE cases SET created_at = datetime('now','-900 days') "
                   "WHERE id = ?", (appeal["case_id"],))
        compliance.enforce_retention()
        assert appeals.get(appeal["id"]) is not None
        assert cases.get_case(appeal["case_id"]) is not None

    def test_unresolved_appeals_are_never_purged(self, subject):
        appeal = appeals.submit(subject, "Still waiting for an answer on this.",
                                decision="VERIFY")
        db.execute("UPDATE appeals SET created_at = datetime('now','-800 days') "
                   "WHERE id = ?", (appeal["id"],))
        appeals.purge_expired()
        assert appeals.get(appeal["id"]) is not None

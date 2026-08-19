"""
Tests for drift and fairness monitoring (improvement #4).

A monitor that never fires is indistinguishable from a monitor that is broken,
so the tests here are mostly *positive controls*: distributions whose drift is
known by construction, and cohort splits whose disparity is known by
construction. If the monitor cannot detect those, it detects nothing.

The second theme is refusal. A fairness dashboard is dangerous precisely when it
is confident, so the sample-size gate is tested as hard as the maths.
"""
import json
import random

import pytest

from engine import cases, db, monitoring


@pytest.fixture()
def rng():
    return random.Random(1234)


def _rows(dimension: str, spec: dict) -> list[dict]:
    """Build decision rows: {cohort: (n, restricted_count)}."""
    out = []
    for cohort, (n, restricted) in spec.items():
        for i in range(n):
            out.append({dimension: cohort,
                        "decision": "BLOCK" if i < restricted else "ALLOW"})
    return out


# =============================================================================
# PSI: positive controls
# =============================================================================
class TestPopulationStabilityIndex:

    def test_identical_distributions_report_stable(self, rng):
        a = [rng.gauss(20, 8) for _ in range(2000)]
        b = [rng.gauss(20, 8) for _ in range(2000)]
        assert monitoring._band(monitoring._psi(a, b)) == "stable"

    def test_a_large_shift_is_detected(self, rng):
        a = [rng.gauss(20, 8) for _ in range(2000)]
        b = [rng.gauss(40, 8) for _ in range(2000)]
        psi = monitoring._psi(a, b)
        assert psi > 0.25
        assert monitoring._band(psi) == "significant shift"

    def test_psi_grows_monotonically_with_the_size_of_the_shift(self, rng):
        base = [rng.gauss(20, 8) for _ in range(3000)]
        psis = [monitoring._psi(base, [rng.gauss(20 + d, 8) for _ in range(3000)])
                for d in (0, 4, 10, 20)]
        assert psis == sorted(psis), f"PSI did not increase with drift: {psis}"

    def test_a_variance_collapse_is_detected(self, rng):
        """Same mean, far narrower spread — a real failure mode PSI must catch."""
        a = [rng.gauss(20, 8) for _ in range(2000)]
        b = [rng.gauss(20, 0.5) for _ in range(2000)]
        assert monitoring._band(monitoring._psi(a, b)) == "significant shift"

    def test_an_empty_bucket_does_not_produce_infinity(self, rng):
        """
        A bucket nobody lands in makes the log term infinite unless floored.
        Without the epsilon this returns inf and every dashboard reads
        "infinite drift".
        """
        a = [rng.gauss(20, 8) for _ in range(1000)]
        b = [100.0] * 1000
        psi = monitoring._psi(a, b)
        assert psi is not None
        assert psi == psi and psi != float("inf")     # not NaN, not infinite

    def test_tiny_samples_return_none_rather_than_a_number(self):
        assert monitoring._psi([1.0, 2.0], [3.0, 4.0]) is None
        assert monitoring._band(None) == "insufficient data"


# =============================================================================
# Fairness: positive controls and refusals
# =============================================================================
class TestDisparateImpact:

    def test_an_even_split_is_not_flagged(self):
        n = monitoring.MIN_COHORT_N + 10
        rates = monitoring._selection_rates(
            _rows("region", {"a": (n, n // 3), "b": (n, n // 3)}), "region")
        di = monitoring._disparate_impact(rates)
        assert di["ratio"] == pytest.approx(1.0, abs=0.05)
        assert di["flag"] is False

    def test_a_three_to_one_disparity_is_flagged(self):
        n = monitoring.MIN_COHORT_N + 10
        rates = monitoring._selection_rates(
            _rows("region", {"a": (n, int(n * 0.6)), "b": (n, int(n * 0.2))}),
            "region")
        di = monitoring._disparate_impact(rates)
        assert di["flag"] is True
        assert di["ratio"] < 0.8
        assert di["most_restricted"] == "a"
        assert di["least_restricted"] == "b"

    def test_the_four_fifths_boundary_behaves_as_documented(self):
        n = 200
        rates = monitoring._selection_rates(
            _rows("region", {"a": (n, 100), "b": (n, 79)}), "region")
        assert monitoring._disparate_impact(rates)["flag"] is True
        rates = monitoring._selection_rates(
            _rows("region", {"a": (n, 100), "b": (n, 81)}), "region")
        assert monitoring._disparate_impact(rates)["flag"] is False

    def test_a_cohort_below_the_minimum_gets_no_rate(self):
        rates = monitoring._selection_rates(
            _rows("region", {"tiny": (3, 3)}), "region")
        assert rates["tiny"]["selection_rate"] is None
        assert rates["tiny"]["sufficient"] is False
        assert rates["tiny"]["n"] == 3        # the raw count is still honest

    def test_small_cohorts_are_excluded_rather_than_treated_as_zero(self):
        """
        A tiny unrestricted cohort must not manufacture a reassuring ratio. If
        it counted as 0.0, the ratio would be 0 and flag; if it were silently
        dropped without a note, the dashboard would look clean. Neither is
        acceptable — it is excluded AND the count of comparable cohorts drops.
        """
        n = monitoring.MIN_COHORT_N + 10
        rows = _rows("region", {"big": (n, n // 2), "tiny": (4, 0)})
        di = monitoring._disparate_impact(
            monitoring._selection_rates(rows, "region"))
        assert di["comparable_cohorts"] == 1
        assert di["ratio"] is None
        assert di["flag"] is False
        assert "at least two cohorts" in di["note"]

    def test_no_comparison_is_made_from_a_single_cohort(self):
        n = monitoring.MIN_COHORT_N + 5
        di = monitoring._disparate_impact(
            monitoring._selection_rates(_rows("region", {"only": (n, 5)}), "region"))
        assert di["ratio"] is None and di["flag"] is False


# =============================================================================
# Honesty of the report
# =============================================================================
class TestReportHonesty:

    def test_the_fairness_report_declares_its_cohorts_synthetic(self):
        report = monitoring.fairness(days=30)
        assert report["synthetic_cohorts"] is True
        assert "FICTIONAL" in report["warning"]
        assert "not" in report["warning"].lower()

    def test_the_full_report_states_the_prototype_limitation(self):
        assert "cannot produce statistically meaningful" in \
               monitoring.report()["honest_summary"]

    def test_cohort_attributes_are_marked_in_every_profile(self):
        """The fixture data itself must say it is fictional, not just the code."""
        import os
        from engine.config_loader import backend_path
        users = backend_path("data", "users")
        for name in sorted(os.listdir(users)):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(users, name), encoding="utf-8") as f:
                data = json.load(f)
            cohort = data.get("synthetic_cohort")
            assert cohort, f"{name} has no cohort block"
            assert "FICTIONAL" in cohort.get("_note", "")

    def test_every_dimension_is_reported_even_when_empty(self):
        dims = monitoring.fairness(days=30)["dimensions"]
        assert set(dims) == set(monitoring.COHORT_DIMENSIONS)

    def test_drift_reports_insufficient_rather_than_a_fabricated_psi(self):
        drift = monitoring.score_drift()
        if not drift["sufficient"]:
            assert drift["psi"] is None
            assert drift["band"] == "insufficient data"
            assert "at least" in drift["note"]


# =============================================================================
# Wiring to real data
# =============================================================================
class TestWiring:

    def test_scored_decisions_are_joined_to_their_cohort(self, user_factory):
        user, _pw = user_factory(profile_id="bikash_migrant")
        db.log_activity(user["id"], "pre_otp_check",
                        {"decision": "BLOCK", "risk": 90.0})
        rows = monitoring._scored_decisions(30)
        mine = [r for r in rows if r["user_id"] == user["id"]]
        assert mine, "the decision was not picked up"
        assert mine[0]["region"] == "abroad"
        assert mine[0]["operator"] == "NTC"

    def test_upheld_appeals_are_attributed_to_a_cohort(self, user_factory):
        from engine import appeals
        analyst, _ = user_factory(role="admin")
        user, _pw = user_factory(profile_id="bikash_migrant")
        appeal = appeals.submit(user, "I work in Doha, that sign-in was me.",
                                decision="BLOCK", risk_score=90.0)
        appeals.review(appeal["id"], analyst["id"], uphold=True,
                       reason_code="FP01", evidence="Employer letter checked.")
        by_cohort = monitoring._upheld_appeals_by_cohort("region", 30)
        assert by_cohort.get("abroad", {}).get("upheld", 0) >= 1

    def test_an_unknown_profile_does_not_crash_the_join(self, user_factory):
        user, _pw = user_factory(profile_id="does_not_exist")
        db.log_activity(user["id"], "pre_otp_check", {"decision": "ALLOW", "risk": 5})
        rows = monitoring._scored_decisions(30)
        mine = [r for r in rows if r["user_id"] == user["id"]]
        assert mine and mine[0]["region"] == "unknown"


# =============================================================================
# Self-validation harness
# =============================================================================
class TestSelfValidationHarness:

    @pytest.fixture(scope="class")
    def validation(self):
        from evaluate_monitoring import (_validate_disparate_impact,
                                         _validate_psi, _validate_sample_gate)
        return (_validate_psi() + _validate_disparate_impact()
                + _validate_sample_gate())

    def test_every_self_validation_check_passes(self, validation):
        failures = [c for c in validation if not c["pass"]]
        assert failures == [], f"monitor self-validation failed: {failures}"

    def test_the_harness_actually_exercises_both_outcomes(self, validation):
        """A validation suite where nothing ever flags proves nothing."""
        flags = [c.get("flagged") for c in validation if "flagged" in c]
        assert True in flags and False in flags


# =============================================================================
# HTTP surface
# =============================================================================
class TestMonitoringRoutes:

    def test_the_report_is_admin_only(self, client):
        assert client.get("/api/admin/monitoring").status_code == 401

    def test_an_admin_gets_drift_fairness_and_feedback(self, client, signed_in):
        _admin, _headers = signed_in(role="admin")
        body = client.get("/api/admin/monitoring").get_json()
        assert "drift" in body and "fairness" in body and "feedback" in body
        assert body["fairness"]["synthetic_cohorts"] is True

    def test_the_feedback_endpoint_names_its_label_source(self, client, signed_in):
        _admin, _headers = signed_in(role="admin")
        body = client.get("/api/admin/feedback").get_json()
        assert "analyst" in body["measured_false_positive_rate"]["label_source"]

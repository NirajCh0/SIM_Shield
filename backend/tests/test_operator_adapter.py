"""
Tests for the operator adapter boundary (improvement #1).

The centrepiece is `TestFailOpen`, which proves the non-negotiable property
behaviourally, for every degradation mode, rather than by inspecting config:

    an operator problem can never make an otherwise legitimate login worse.

Everything else guards the properties that make that guarantee trustworthy —
typed results with no silent defaults, consent enforced at the boundary, no
personal location data in logs or fixtures, and a CAMARA adapter that is a
placeholder in fact and not only in its docstring.
"""
import io
import json
import os
import re

import pytest

from engine import compliance, operator, signals
from engine.config_loader import backend_path, load_config
from engine.detector import score_login
from engine.operator_adapter import (ConsentState, OperatorAdapter,
                                     OperatorResult, OperatorStatus,
                                     get_adapter, operator_config, safe_call,
                                     set_adapter)
from engine.operator_camara import CamaraNotImplemented, CamaraOperatorAdapter
from engine.operator_mock import FAULTS, MockOperatorAdapter
from engine.profiles import load as load_profile

SEVERITY = {"ALLOW": 0, "MONITOR": 1, "VERIFY": 2, "BLOCK": 3}

#: Every way the feed can misbehave. `none` is the baseline, so it is excluded.
DEGRADED_FAULTS = [f for f in FAULTS if f != "none"]

#: An ordinary, legitimate login by a long-standing subscriber at a safe zone,
#: whose SIM the network reports on the other side of a border. With the
#: operator answering this is a genuine VERIFY; with the operator broken it must
#: fall back to the login's own merits, never harden.
CLEAN_LOGIN = {
    "current_location": {"lat": 27.7154, "lon": 85.3123},   # Thamel
    "imei": "356938035643809",
    "logins_last_24h": 1,
    "failed_logins_last_24h": 0,
    "sim_network_area": "Delhi",
}


@pytest.fixture()
def midday():
    """A timestamp outside the odd-hour window, so it cannot skew a probe."""
    from datetime import datetime
    return datetime.now().replace(hour=12, minute=0, second=0,
                                  microsecond=0).isoformat(timespec="seconds")


@pytest.fixture(scope="module")
def degradation_matrix():
    """
    The full matrix: 9 conditions x (40 scenarios + 3 probes).

    Module-scoped because building it re-scores the whole suite ten times, and
    two separate test classes assert against it.
    """
    from evaluate_operator import build_matrix
    set_adapter(None)
    return build_matrix()


@pytest.fixture()
def mock_adapter():
    """Install a fresh mock adapter and always restore the default afterwards."""
    adapter = MockOperatorAdapter()
    set_adapter(adapter)
    yield adapter
    set_adapter(None)


# =============================================================================
# The guarantee: operator problems never harden a decision
# =============================================================================
class TestFailOpen:

    @pytest.mark.parametrize("fault", DEGRADED_FAULTS)
    def test_degradation_never_raises_the_risk_score(self, fault, midday, mock_adapter):
        profile = load_profile("aarav_safe")
        attempt = dict(CLEAN_LOGIN, timestamp=midday)

        mock_adapter.set_fault("none")
        baseline = score_login(attempt, profile)

        mock_adapter.set_fault(fault)
        mock_adapter.reset_quota()
        degraded = score_login(attempt, profile)

        assert degraded["risk_score"] <= baseline["risk_score"], (
            f"{fault} RAISED the score {baseline['risk_score']} -> "
            f"{degraded['risk_score']}: operator failure must never add risk")
        assert SEVERITY[degraded["decision"]] <= SEVERITY[baseline["decision"]]

    @pytest.mark.parametrize("fault", DEGRADED_FAULTS)
    def test_outage_alone_cannot_produce_block(self, fault, midday, mock_adapter):
        """
        The explicit proof requested: missing operator data, on a login that is
        otherwise entirely ordinary, must not reach BLOCK.

        The profile is a five-year-old SIM on a known device at a registered
        safe zone at midday — there is no legitimate reason for any decision
        beyond ALLOW here, and certainly not because a partner API is down.
        """
        profile = load_profile("aarav_safe")
        attempt = {"current_location": {"lat": 27.7154, "lon": 85.3123},
                   "imei": "356938035643809", "timestamp": midday,
                   "logins_last_24h": 1, "failed_logins_last_24h": 0}
        mock_adapter.set_fault(fault)
        mock_adapter.reset_quota()
        result = score_login(attempt, profile)
        assert result["decision"] != "BLOCK", (
            f"operator fault {fault!r} produced BLOCK for a clean login")
        assert result["decision"] == "ALLOW", (
            f"operator fault {fault!r} degraded a clean login to "
            f"{result['decision']}")

    @pytest.mark.parametrize("fault", DEGRADED_FAULTS)
    def test_mismatch_flag_is_never_set_on_a_degraded_result(self, fault, midday,
                                                             mock_adapter):
        profile = load_profile("aarav_safe")
        attempt = dict(CLEAN_LOGIN, timestamp=midday)
        mock_adapter.set_fault(fault)
        mock_adapter.reset_quota()
        mm = operator.location_mismatch(profile, attempt)
        assert mm["mismatch"] is False
        assert mm["available"] is False
        assert mm["km"] is None
        assert mm["status"] != OperatorStatus.AVAILABLE.value

    @pytest.mark.parametrize("fault", DEGRADED_FAULTS)
    def test_no_degraded_flag_reaches_the_behavioural_score(self, fault, midday,
                                                            mock_adapter):
        profile = load_profile("aarav_safe")
        attempt = dict(CLEAN_LOGIN, timestamp=midday)
        mock_adapter.set_fault(fault)
        mock_adapter.reset_quota()
        behav = signals.evaluate(attempt, profile, load_config())
        ids = [f["id"] for f in behav["flags"]]
        assert "sim_location_mismatch" not in ids
        assert behav["features"]["sim_location_mismatch"] == 0

    def test_working_operator_still_detects_the_mismatch(self, midday, mock_adapter):
        """
        The guarantee must not be satisfied by making the signal useless. With
        the operator answering, the same login IS elevated.
        """
        profile = load_profile("aarav_safe")
        attempt = dict(CLEAN_LOGIN, timestamp=midday)
        clean = score_login({k: v for k, v in attempt.items()
                             if k != "sim_network_area"}, profile)
        flagged = score_login(attempt, profile)
        assert flagged["risk_score"] > clean["risk_score"]
        assert SEVERITY[flagged["decision"]] > SEVERITY[clean["decision"]]

    def test_matching_sim_location_adds_no_risk(self, midday, mock_adapter):
        """A SIM where it should be is not corroboration; it simply adds nothing."""
        profile = load_profile("aarav_safe")
        base = {"current_location": {"lat": 27.7154, "lon": 85.3123},
                "imei": "356938035643809", "timestamp": midday,
                "logins_last_24h": 1, "failed_logins_last_24h": 0}
        without = score_login(base, profile)
        with_match = score_login(dict(base, sim_network_area="Thamel"), profile)
        assert with_match["risk_score"] == without["risk_score"]

    def test_there_is_no_fail_open_configuration_key(self):
        """
        Fail-open is structural. A key would imply it can be switched off, and
        anything that can be switched off eventually is.
        """
        assert "fail_open" not in (load_config().get("operator") or {})
        raw = io.open(backend_path("config.yaml"), encoding="utf-8").read()
        assert not re.search(r"^\s*fail_open\s*:", raw, re.MULTILINE)


# =============================================================================
# Typed results: no silent defaults
# =============================================================================
class TestTypedResult:

    def test_every_critical_field_must_be_supplied(self):
        """Status, source, consent, freshness and latency cannot be defaulted."""
        with pytest.raises(TypeError):
            OperatorResult(status=OperatorStatus.AVAILABLE)   # type: ignore[call-arg]

    def test_usable_requires_available_fresh_consented_and_populated(self, mock_adapter):
        profile = load_profile("aarav_safe")
        subject = {"id": "aarav_safe", "profile": profile,
                   "attempt": {"sim_network_area": "Delhi"}}
        good = mock_adapter.sim_location(
            subject, claimed={"lat": 27.7154, "lon": 85.3123},
            consent=ConsentState.GRANTED)
        assert good.status is OperatorStatus.AVAILABLE
        assert good.usable is True

        # Each individual defect is enough to make it unusable.
        from dataclasses import replace
        assert replace(good, fresh=False).usable is False
        assert replace(good, consent=ConsentState.WITHDRAWN).usable is False
        assert replace(good, data=None).usable is False
        assert replace(good, status=OperatorStatus.STALE).usable is False

    def test_assumed_colocation_is_typed_and_never_usable(self, mock_adapter):
        """
        No operator fix means the device's own location is reported for
        transparency — but as an ASSUMPTION, which cannot be scored. Treating it
        as evidence would mean every user trivially "matches" themselves.
        """
        profile = load_profile("aarav_safe")     # carries no sim_network_area
        result = mock_adapter.sim_location(
            {"id": "aarav_safe", "profile": profile, "attempt": {}},
            claimed={"lat": 27.7154, "lon": 85.3123}, consent=ConsentState.GRANTED)
        assert result.status is OperatorStatus.ASSUMED_COLOCATED
        assert result.usable is False
        assert result.data.origin == "device_assumption"

    def test_result_reports_measured_latency_and_named_source(self, mock_adapter):
        profile = load_profile("aarav_safe")
        result = mock_adapter.sim_swap_check(
            {"id": "aarav_safe", "profile": profile, "attempt": {}},
            max_age_days=7, consent=ConsentState.GRANTED)
        assert result.latency_ms >= 0.0
        assert result.source == MockOperatorAdapter.name
        assert result.simulated is True
        assert result.age_seconds is not None

    def test_every_status_has_a_user_facing_message(self):
        for status in OperatorStatus:
            result = OperatorResult(
                status=status, source="t", consent=ConsentState.GRANTED,
                fresh=False, age_seconds=None, latency_ms=0.0, simulated=True,
                operation="sim_location")
            assert result.explain()["message"]
            assert result.explain()["affects_risk"] is result.usable

    def test_sim_swap_check_reports_unknown_not_false_when_degraded(self, mock_adapter):
        """
        "We could not check" must not be reported as "no swap happened". That
        would be a false reassurance to the subscriber.
        """
        mock_adapter.set_fault("unavailable")
        out = operator.sim_swap_check(load_profile("sita_swapped"))
        assert out["swapped"] is None
        assert out["usable"] is False


# =============================================================================
# safe_call: the guarantee survives a badly written adapter
# =============================================================================
class TestSafeCall:

    def test_an_adapter_that_raises_becomes_a_degraded_result(self):
        class Exploding(OperatorAdapter):
            name = "test:exploding"

            def sim_location(self, subject, *, claimed, consent):
                raise RuntimeError("boom")

        result = safe_call(Exploding(), "sim_location", {"id": "x"},
                           ConsentState.GRANTED, claimed=None)
        assert result.status is OperatorStatus.UNAVAILABLE
        assert result.usable is False
        assert "RuntimeError" in result.degraded_reason

    def test_an_adapter_returning_garbage_becomes_malformed(self):
        class Garbage(OperatorAdapter):
            name = "test:garbage"

            def sim_location(self, subject, *, claimed, consent):
                return {"lat": 1, "lon": 2}          # not an OperatorResult

        result = safe_call(Garbage(), "sim_location", {"id": "x"},
                           ConsentState.GRANTED, claimed=None)
        assert result.status is OperatorStatus.MALFORMED
        assert result.usable is False

    def test_an_over_budget_result_is_downgraded_to_timeout(self):
        budget = float(operator_config()["timeout_ms"])

        class Slow(OperatorAdapter):
            name = "test:slow"

            def sim_location(self, subject, *, claimed, consent):
                from engine.operator_adapter import SimLocationData
                return OperatorResult(
                    status=OperatorStatus.AVAILABLE, source=self.name,
                    consent=consent, fresh=True, age_seconds=0.0,
                    latency_ms=budget + 1000.0, simulated=True,
                    operation="sim_location",
                    data=SimLocationData(area="Delhi", country="India",
                                         cell_id="CELL-X", distance_km=800.0,
                                         distance_band="500–2,000 km",
                                         origin="operator_feed"))

        result = safe_call(Slow(), "sim_location", {"id": "x"},
                           ConsentState.GRANTED, claimed=None)
        assert result.status is OperatorStatus.TIMEOUT
        assert result.usable is False

    def test_a_broken_adapter_still_cannot_block_a_clean_login(self, midday):
        class Exploding(OperatorAdapter):
            name = "test:exploding"

            def sim_location(self, subject, *, claimed, consent):
                raise RuntimeError("boom")

            def sim_swap_check(self, subject, *, max_age_days, consent):
                raise RuntimeError("boom")

        set_adapter(Exploding())
        try:
            result = score_login(
                {"current_location": {"lat": 27.7154, "lon": 85.3123},
                 "imei": "356938035643809", "timestamp": midday,
                 "logins_last_24h": 1, "failed_logins_last_24h": 0},
                load_profile("aarav_safe"))
            assert result["decision"] == "ALLOW"
        finally:
            set_adapter(None)


# =============================================================================
# Consent, enforced at the boundary
# =============================================================================
class TestConsent:

    def test_missing_consent_is_not_permission(self):
        """A record that says nothing resolves to UNKNOWN, which denies."""
        state = compliance.operator_consent_state({"user_id": "nobody"}, {})
        assert state is ConsentState.UNKNOWN
        assert state.permits_lookup is False

    def test_explicit_grant_permits_and_withdrawal_denies(self):
        assert compliance.operator_consent_state(
            {"operator_consent": True}, {}) is ConsentState.GRANTED
        assert compliance.operator_consent_state(
            {"operator_consent": False}, {}) is ConsentState.WITHDRAWN

    def test_an_attempt_may_withdraw_consent_for_a_single_check(self):
        state = compliance.operator_consent_state(
            {"operator_consent": True}, {"operator_consent": False})
        assert state is ConsentState.WITHDRAWN

    def test_withdrawn_consent_stops_the_lookup_and_adds_no_risk(self, midday,
                                                                 mock_adapter):
        profile = dict(load_profile("aarav_safe"), operator_consent=False)
        attempt = dict(CLEAN_LOGIN, timestamp=midday)
        mm = operator.location_mismatch(profile, attempt)
        assert mm["status"] == OperatorStatus.CONSENT_DENIED.value
        assert mm["mismatch"] is False
        assert score_login(attempt, profile)["decision"] == "ALLOW"

    def test_every_synthetic_profile_states_a_consent_decision(self):
        """No profile may rely on an implicit default."""
        users = backend_path("data", "users")
        missing = []
        for name in sorted(os.listdir(users)):
            if not name.endswith(".json"):
                continue
            data = json.load(io.open(os.path.join(users, name), encoding="utf-8"))
            if "operator_consent" not in data:
                missing.append(name)
        assert missing == [], f"profiles with no consent decision: {missing}"

    def test_adapter_refuses_the_lookup_itself(self, mock_adapter):
        """Defence in depth: the adapter re-checks rather than trusting the caller."""
        result = mock_adapter.sim_location(
            {"id": "x", "profile": {"sim_network_area": "Delhi"}, "attempt": {}},
            claimed={"lat": 27.7154, "lon": 85.3123},
            consent=ConsentState.WITHDRAWN)
        assert result.status is OperatorStatus.CONSENT_DENIED
        assert result.data is None


# =============================================================================
# Privacy at the boundary
# =============================================================================
COORD_KEYS = ("lat", "lon", "latitude", "longitude", "coordinates")
IDENTIFIER_KEYS = ("phone", "msisdn", "imsi", "iccid", "phone_number")


def _walk(obj, path="$"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield path, k, v
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk(v, f"{path}[{i}]")


class TestPrivacy:

    def test_adapter_results_carry_no_coordinates_or_identifiers(self, mock_adapter):
        profile = load_profile("aarav_safe")
        loc = operator.get_sim_location(
            profile, {"current_location": {"lat": 27.7154, "lon": 85.3123},
                      "sim_network_area": "Delhi"})
        for _path, key, _value in _walk(loc):
            assert key.lower() not in COORD_KEYS, f"coordinate {key!r} in result"
            assert key.lower() not in IDENTIFIER_KEYS, f"identifier {key!r} in result"

    def test_the_location_payload_type_has_no_coordinate_field(self):
        from dataclasses import fields

        from engine.operator_adapter import SimLocationData
        names = {f.name for f in fields(SimLocationData)}
        assert not names & set(COORD_KEYS)

    def test_audit_fields_are_an_allowlist_with_no_location(self, mock_adapter):
        profile = load_profile("aarav_safe")
        subject = {"id": "aarav_safe", "profile": profile,
                   "attempt": {"sim_network_area": "Delhi"}}
        result = mock_adapter.sim_location(
            subject, claimed={"lat": 27.7154, "lon": 85.3123},
            consent=ConsentState.GRANTED)
        fields_ = result.audit_fields()
        assert "area" not in fields_ and "cell_id" not in fields_
        for key in fields_:
            assert key.lower() not in COORD_KEYS + IDENTIFIER_KEYS
        blob = json.dumps(fields_)
        assert "Delhi" not in blob, "the reported area leaked into the audit record"

    def test_written_audit_records_contain_no_location(self, tmp_data):
        """Exercised against the real writer, not just the field allowlist."""
        log = str(tmp_data / "operator_audit.log")
        comp = dict(compliance.load_compliance())

        set_adapter(MockOperatorAdapter())
        try:
            with compliance.redirect_audit(log):
                operator.location_mismatch(
                    load_profile("aarav_safe"),
                    {"current_location": {"lat": 27.7154, "lon": 85.3123},
                     "sim_network_area": "Delhi"})
        finally:
            set_adapter(None)

        assert comp["audit"]["enabled"]
        written = io.open(log, encoding="utf-8").read()
        assert written.strip(), "the operator access was not audited at all"
        assert "Delhi" not in written
        assert "27.7" not in written and "85.3" not in written
        record = json.loads(written.strip().splitlines()[-1])
        assert record["kind"] == "operator_access"
        assert record["status"] == OperatorStatus.AVAILABLE.value
        assert "CELL-" not in json.dumps(record)

    def test_bulk_evaluation_does_not_pollute_the_subscriber_audit_log(self, tmp_data):
        """
        The degradation harness performs thousands of lookups. Auditing them
        into the real chain would bury genuine access records and make every
        later append slower — so it gets its own sink, without auditing being
        switched off.
        """
        sink = str(tmp_data / "eval_sink.log")
        real = str(tmp_data / "real_audit.log")
        with compliance.redirect_audit(real):
            adapter = MockOperatorAdapter()
            set_adapter(adapter)
            try:
                with compliance.redirect_audit(sink):
                    operator.location_mismatch(
                        load_profile("aarav_safe"),
                        {"current_location": {"lat": 27.7154, "lon": 85.3123},
                         "sim_network_area": "Delhi"})
                assert os.path.exists(sink), "the harness sink was not written"
                assert not os.path.exists(real), "a lookup leaked into the real log"
                # The override must unwind, or later real accesses go missing.
                operator.location_mismatch(
                    load_profile("aarav_safe"),
                    {"current_location": {"lat": 27.7154, "lon": 85.3123}})
                assert os.path.exists(real), "auditing did not resume afterwards"
            finally:
                set_adapter(None)

    def test_degraded_lookups_are_audited_too(self, tmp_data):
        """A denied or failed lookup is the one you most want a record of."""
        log = str(tmp_data / "operator_audit_denied.log")
        set_adapter(MockOperatorAdapter(fault="unavailable"))
        try:
            with compliance.redirect_audit(log):
                operator.location_mismatch(
                    load_profile("aarav_safe"),
                    {"current_location": {"lat": 27.7154, "lon": 85.3123}})
        finally:
            set_adapter(None)
        record = json.loads(io.open(log, encoding="utf-8").read().strip().splitlines()[-1])
        assert record["status"] == OperatorStatus.UNAVAILABLE.value
        assert record["usable"] is False

    def test_mock_fixtures_declare_areas_not_coordinates(self):
        """
        Operator-supplied locations in fixtures are place NAMES. (A login's own
        `current_location` is a real input the browser supplies and is not
        operator data, so it is out of scope for this rule.)
        """
        for rel in ("scenarios.py", "evaluate_ml.py", "evaluate_operator.py"):
            text = io.open(backend_path(rel), encoding="utf-8").read()
            assert "sim_network_location" not in text, (
                f"{rel} still pins an operator coordinate")

    def test_the_degradation_report_contains_no_location_data(self, degradation_matrix):
        blob = json.dumps(degradation_matrix)
        for key, _v in ((k, v) for _p, k, v in _walk(json.loads(blob))):
            assert key.lower() not in COORD_KEYS + IDENTIFIER_KEYS
        assert "Delhi" not in blob and "Biratnagar" not in blob


# =============================================================================
# The mock preserves the behaviour the project already had
# =============================================================================
class TestMockPreservesBehaviour:

    def test_the_default_adapter_is_the_mock(self):
        set_adapter(None)
        assert isinstance(get_adapter(), MockOperatorAdapter)
        assert get_adapter().simulated is True

    def test_the_cross_border_block_scenario_still_blocks(self, mock_adapter):
        from scenarios import SCENARIOS
        sc = next(s for s in SCENARIOS
                  if s["name"] == "Spoofed location, SIM says otherwise")
        assert score_login(sc["attempt"], sc["profile"])["decision"] == "BLOCK"

    def test_a_matching_sim_scenario_still_verifies(self, mock_adapter):
        from scenarios import SCENARIOS
        sc = next(s for s in SCENARIOS
                  if s["name"] == "Session used from another country")
        assert score_login(sc["attempt"], sc["profile"])["decision"] == "VERIFY"

    def test_legacy_coordinate_fixtures_still_resolve(self, mock_adapter):
        """Older fixtures keep working, but the coordinate is discarded."""
        profile = dict(load_profile("aarav_safe"),
                       sim_network_location={"lat": 28.6139, "lon": 77.2090})
        mm = operator.location_mismatch(
            profile, {"current_location": {"lat": 27.7154, "lon": 85.3123}})
        assert mm["available"] is True
        assert mm["mismatch"] is True
        assert mm["sim_area"] == "Delhi"
        assert "lat" not in mm and "lon" not in mm

    def test_unknown_area_names_degrade_rather_than_guess(self, mock_adapter):
        profile = dict(load_profile("aarav_safe"), sim_network_area="Atlantis")
        mm = operator.location_mismatch(
            profile, {"current_location": {"lat": 27.7154, "lon": 85.3123}})
        assert mm["mismatch"] is False


# =============================================================================
# Rate limiting
# =============================================================================
class TestRateLimit:

    def test_real_quota_exhaustion_degrades_rather_than_erroring(self, mock_adapter):
        profile = load_profile("aarav_safe")
        attempt = {"current_location": {"lat": 27.7154, "lon": 85.3123},
                   "sim_network_area": "Delhi"}
        limit = int(operator_config()["rate_limit_per_minute"])
        mock_adapter.reset_quota()

        statuses = [operator.location_mismatch(profile, attempt)["status"]
                    for _ in range(limit + 5)]
        assert statuses[0] == OperatorStatus.AVAILABLE.value
        assert statuses[-1] == OperatorStatus.RATE_LIMITED.value

    def test_exhausted_quota_does_not_raise_risk(self, midday, mock_adapter):
        profile = load_profile("aarav_safe")
        attempt = dict(CLEAN_LOGIN, timestamp=midday)
        mock_adapter.reset_quota()
        for _ in range(int(operator_config()["rate_limit_per_minute"]) + 2):
            operator.location_mismatch(profile, attempt)
        assert score_login(attempt, profile)["decision"] == "ALLOW"


# =============================================================================
# The CAMARA adapter is a placeholder in fact, not only in prose
# =============================================================================
class TestCamaraPlaceholder:

    def test_it_is_marked_unimplemented_and_simulated(self):
        adapter = CamaraOperatorAdapter()
        assert adapter.implemented is False
        assert adapter.simulated is True

    @pytest.mark.parametrize("op,kwargs", [
        ("sim_location", {"claimed": {"lat": 27.7, "lon": 85.3}}),
        ("sim_swap_check", {"max_age_days": 7}),
    ])
    def test_every_operation_returns_not_configured(self, op, kwargs):
        result = getattr(CamaraOperatorAdapter(), op)(
            {"id": "x", "profile": {}, "attempt": {}},
            consent=ConsentState.GRANTED, **kwargs)
        assert result.status is OperatorStatus.NOT_CONFIGURED
        assert result.usable is False
        assert result.data is None

    def test_selecting_it_degrades_but_never_blocks(self, midday):
        set_adapter(CamaraOperatorAdapter())
        try:
            result = score_login(dict(CLEAN_LOGIN, timestamp=midday),
                                 load_profile("aarav_safe"))
            assert result["decision"] == "ALLOW"
        finally:
            set_adapter(None)

    def test_it_contains_no_http_client_or_endpoint(self):
        """
        The module must stay inert: no transport library, no hostname, no
        credential literal. A docstring saying "placeholder" is not a control.
        """
        source = io.open(backend_path("engine", "operator_camara.py"),
                         encoding="utf-8").read()
        for banned in ("import requests", "import httpx", "urllib.request",
                       "http://", "https://", "socket."):
            assert banned not in source, f"{banned!r} appears in the placeholder"

    def test_no_credentials_are_configured_anywhere(self):
        from engine.operator_camara import REQUIRED_SETTINGS
        for name in REQUIRED_SETTINGS:
            assert not os.environ.get(name), f"{name} is set — this must stay unwired"

    def test_the_tripwire_raises_if_anyone_wires_a_transport_in(self):
        with pytest.raises(CamaraNotImplemented):
            CamaraOperatorAdapter()._perform_request("GET", "/anything")


# =============================================================================
# The degradation matrix itself
# =============================================================================
class TestDegradationMatrix:

    @pytest.fixture()
    def matrix(self, degradation_matrix):
        return degradation_matrix

    def test_it_covers_all_nine_required_conditions(self, matrix):
        expected = {"available", "unavailable", "timeout", "stale", "partial",
                    "disagreement", "rate_limited", "malformed",
                    "consent_withdrawn"}
        assert {c["condition"] for c in matrix["conditions"]} == expected

    def test_no_condition_produces_a_fail_closed_regression(self, matrix):
        assert matrix["fail_closed_regressions_total"] == 0
        assert matrix["probe_fail_closed_total"] == 0
        assert matrix["pass"] is True

    def test_every_degraded_condition_reports_zero_usable_lookups(self, matrix):
        for c in matrix["conditions"]:
            if c["condition"] == "available":
                continue
            assert c["operator_usable_count"] == 0, c["condition"]
            assert c["mismatch_flagged_count"] == 0, c["condition"]

    def test_the_probes_show_the_signal_actually_doing_work(self, matrix):
        """
        Guards against a vacuous pass. Under `available` the mismatch probe must
        be elevated; under every degraded condition it must fall back — with a
        real, negative score delta.
        """
        by_condition = {c["condition"]: c for c in matrix["conditions"]}
        probe = "clean login, SIM reported abroad"

        base = next(p for p in by_condition["available"]["isolating_probes"]
                    if p["probe"] == probe)
        assert base["mismatch_flagged"] is True
        assert base["decision"] in ("VERIFY", "BLOCK")

        for name, c in by_condition.items():
            if name == "available":
                continue
            row = next(p for p in c["isolating_probes"] if p["probe"] == probe)
            assert row["mismatch_flagged"] is False, name
            assert row["risk_delta_vs_available"] < 0, (
                f"{name} did not actually lose the signal")
            assert row["fail_closed"] is False, name

    def test_the_report_states_that_integration_is_simulated(self, matrix):
        assert matrix["simulated"] is True
        assert "SIMULATED" in matrix["note"]


# =============================================================================
# HTTP surface
# =============================================================================
class TestOperatorRoutes:

    def test_health_declares_the_adapter_and_fail_open_posture(self, client):
        body = client.get("/api/operator/health").get_json()
        assert body["simulated"] is True
        assert body["fail_open"] is True
        assert body["adapter"].startswith("mock:")
        assert set(body["consent_states"]) >= {"granted", "withdrawn"}

    def test_sim_location_still_requires_authentication(self, client):
        assert client.get(
            "/api/operator/sim-location?user_id=aarav_safe").status_code == 401

    def test_sim_location_returns_an_area_and_no_coordinates(self, client, signed_in):
        # Link the account to a synthetic profile: the route deliberately
        # refuses to disclose a SIM the caller does not own.
        user, _headers = signed_in(profile_id="aarav_safe")
        r = client.get(f"/api/operator/sim-location?user_id={user['profile_id']}"
                       "&lat=27.7154&lon=85.3123")
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body["simulated"] is True
        assert "status" in body and "explain" in body
        for _p, key, _v in _walk(body):
            assert key.lower() not in COORD_KEYS + IDENTIFIER_KEYS

    def test_a_degraded_lookup_is_reported_not_hidden(self, client, signed_in,
                                                      monkeypatch):
        # Link the account to a synthetic profile: the route deliberately
        # refuses to disclose a SIM the caller does not own.
        user, _headers = signed_in(profile_id="aarav_safe")
        set_adapter(MockOperatorAdapter(fault="unavailable"))
        try:
            r = client.get(
                f"/api/operator/sim-location?user_id={user['profile_id']}"
                "&lat=27.7154&lon=85.3123")
            assert r.status_code == 200
            body = r.get_json()
            assert body["usable"] is False
            assert body["status"] == OperatorStatus.UNAVAILABLE.value
            assert body["degraded_reason"]
        finally:
            set_adapter(None)

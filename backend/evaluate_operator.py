"""
Operator-degradation evaluation matrix.

Answers one question with measurements rather than assurances: **what happens to
every decision SIMShield makes when the operator feed misbehaves?**

The whole 40-scenario regression suite is re-scored under each of nine operator
conditions. For each condition the harness records the decision distribution and
compares every scenario against its baseline, flagging any case that became MORE
restrictive when operator data got worse.

The pass criterion is strict and one-directional:

    NO scenario may move to a more severe decision because operator data was
    missing, slow, stale, partial, contradictory, rate-limited, malformed or
    unconsented.

Losing the mismatch signal is allowed to make a decision LESS severe — that is
the honest cost of failing open, and it is reported as `weakened` so the
dissertation can state the trade-off with a number instead of a claim.

Run:  python evaluate_operator.py
Writes data/operator_degradation.json (read by the metrics page).

No coordinates, phone numbers or IMSIs appear in the output — the matrix records
decisions, counts and statuses only.
"""
import json

from engine import operator
from engine.config_loader import backend_path
from engine.detector import score_login
from engine.operator_adapter import set_adapter
from engine.operator_mock import MockOperatorAdapter

#: Decision severity, used to detect a fail-CLOSED regression.
SEVERITY = {"ALLOW": 0, "MONITOR": 1, "VERIFY": 2, "BLOCK": 3}

#: The nine conditions, in the order they are reported.
CONDITIONS = [
    ("available", "none",
     "Operator answers normally — the baseline every other row is compared to."),
    ("unavailable", "unavailable",
     "The operator gateway cannot be reached at all."),
    ("timeout", "timeout",
     "The operator accepts the call but does not answer within the budget."),
    ("stale", "stale",
     "A reading is returned but it is older than max_age_seconds."),
    ("partial", "partial",
     "A response arrives with the area field missing."),
    ("disagreement", "disagreement",
     "Two network sources report different areas for the same SIM."),
    ("rate_limited", "rate_limited",
     "The operator quota for this subject is exhausted."),
    ("malformed", "malformed",
     "The operator returns a payload that does not parse."),
    ("consent_withdrawn", "consent_withdrawn",
     "The subscriber has withdrawn consent for network SIM lookups."),
]


# --- isolating probes ---------------------------------------------------------
# The 40-scenario suite alone makes this matrix pass VACUOUSLY. Its one
# operator-dependent case ("Spoofed location, SIM says otherwise") also fires
# eight other flags, whose raw points sum to 305 against a behavioural cap of
# 100 — so removing the 65-point mismatch flag changes the capped score by
# exactly nothing. A table of unchanged rows would then read as "degradation is
# harmless" when it actually only showed "this scenario never depended on the
# signal".
#
# These probes isolate it: an otherwise ordinary login where the SIM-area
# mismatch is the ONLY elevated signal. They give the matrix a measurable
# delta — the signal must move the score when the operator answers, and the
# score must fall back (never rise) when it does not.
PROBES = [
    ("clean login, SIM reported abroad", "aarav_safe",
     {"current_location": {"lat": 27.7154, "lon": 85.3123},   # Thamel, a safe zone
      "imei": "356938035643809", "logins_last_24h": 1, "failed_logins_last_24h": 0,
      "sim_network_area": "Delhi"}),
    ("clean login, SIM reported far inside Nepal", "ramesh_lowrisk",
     {"current_location": {"lat": 27.6786, "lon": 85.2770},   # Kirtipur
      "imei": "353112223334445", "logins_last_24h": 2, "failed_logins_last_24h": 0,
      "sim_network_area": "Biratnagar"}),
    ("clean login, SIM reported at the same place", "aarav_safe",
     {"current_location": {"lat": 27.7154, "lon": 85.3123},
      "imei": "356938035643809", "logins_last_24h": 1, "failed_logins_last_24h": 0,
      "sim_network_area": "Thamel"}),
]


def _run_probes(fault: str) -> list[dict]:
    """Score the isolating probes with one fault active."""
    from datetime import datetime

    from engine.profiles import load as load_profile

    adapter = MockOperatorAdapter(fault=fault)
    set_adapter(adapter)
    try:
        rows = []
        # Midday, so the odd-hour rule cannot contaminate the measurement.
        stamp = datetime.now().replace(hour=12, minute=0, second=0,
                                       microsecond=0).isoformat(timespec="seconds")
        for name, user, attempt in PROBES:
            adapter.reset_quota()
            profile = load_profile(user)
            att = dict(attempt, timestamp=stamp)
            result = score_login(att, profile)
            mm = operator.location_mismatch(profile, att)
            rows.append({"name": name, "decision": result["decision"],
                         "risk_score": result["risk_score"],
                         "operator_status": mm["status"],
                         "mismatch_flagged": mm["mismatch"]})
        return rows
    finally:
        set_adapter(None)


def _run_suite(fault: str) -> list[dict]:
    """Score every scenario with one fault active on the mock adapter."""
    from scenarios import SCENARIOS

    adapter = MockOperatorAdapter(fault=fault)
    set_adapter(adapter)
    try:
        rows = []
        for sc in SCENARIOS:
            adapter.reset_quota()      # each scenario gets a fresh quota window
            attempt = dict(sc["attempt"])
            # A scenario must not be able to override the condition under test.
            attempt.pop("operator_fault", None)
            result = score_login(attempt, sc["profile"])
            mismatch = operator.location_mismatch(sc["profile"], attempt)
            rows.append({
                "name": sc["name"],
                "expected": sc["expected_decision"],
                "decision": result["decision"],
                "risk_score": result["risk_score"],
                "operator_status": mismatch["status"],
                "operator_usable": mismatch["available"],
                "mismatch_flagged": mismatch["mismatch"],
            })
        return rows
    finally:
        set_adapter(None)              # never leave a fault installed


def _distribution(rows: list[dict]) -> dict:
    dist = {k: 0 for k in SEVERITY}
    for r in rows:
        dist[r["decision"]] += 1
    return dist


def build_matrix() -> dict:
    """
    Build the full matrix.

    Audit writes are redirected to their own sink for the duration: this harness
    performs ~6,400 operator lookups, and every one is audited. Left pointed at
    the real log they would bury genuine subscriber-access records in harness
    noise and make each append progressively slower (finding the chain head
    means reading the whole file). Auditing is not disabled — the harness
    produces its own complete, verifiable chain.
    """
    from engine import compliance
    with compliance.redirect_audit(backend_path("data", "operator_eval_audit.log")):
        return _build_matrix()


def _build_matrix() -> dict:
    baseline = _run_suite("none")
    base_by_name = {r["name"]: r for r in baseline}
    probe_baseline = {r["name"]: r for r in _run_probes("none")}

    conditions = []
    fail_closed_total = 0
    probe_regressions = 0
    for label, fault, description in CONDITIONS:
        rows = _run_suite(fault)
        probes = _run_probes(fault)
        probe_rows = []
        for p in probes:
            base = probe_baseline[p["name"]]
            rise = SEVERITY[p["decision"]] - SEVERITY[base["decision"]] > 0
            if rise:
                probe_regressions += 1
            probe_rows.append({
                "probe": p["name"], "decision": p["decision"],
                "risk_score": p["risk_score"],
                "operator_status": p["operator_status"],
                "mismatch_flagged": p["mismatch_flagged"],
                "risk_delta_vs_available": round(
                    p["risk_score"] - base["risk_score"], 1),
                "fail_closed": rise,
            })
        hardened, weakened = [], []
        for r in rows:
            base = base_by_name[r["name"]]
            delta = SEVERITY[r["decision"]] - SEVERITY[base["decision"]]
            if delta > 0:
                hardened.append({"scenario": r["name"],
                                 "baseline": base["decision"],
                                 "degraded": r["decision"],
                                 "risk_delta": round(
                                     r["risk_score"] - base["risk_score"], 1)})
            elif delta < 0:
                weakened.append({"scenario": r["name"],
                                 "baseline": base["decision"],
                                 "degraded": r["decision"],
                                 "risk_delta": round(
                                     r["risk_score"] - base["risk_score"], 1)})
        fail_closed_total += len(hardened)
        statuses = sorted({r["operator_status"] for r in rows})
        # Decision CLASS is coarse: a scenario can lose the whole 65-point
        # mismatch flag and still land in the same band because other signals
        # already carried it. Recording the score movement as well makes that
        # redundancy visible instead of letting an unchanged table imply the
        # operator signal does nothing — or that it changes nothing.
        deltas = [round(r["risk_score"] - base_by_name[r["name"]]["risk_score"], 1)
                  for r in rows]
        moved = [d for d in deltas if d != 0]
        conditions.append({
            "condition": label,
            "description": description,
            "n": len(rows),
            "decision_distribution": _distribution(rows),
            "operator_statuses_observed": statuses,
            "operator_usable_count": sum(1 for r in rows if r["operator_usable"]),
            "mismatch_flagged_count": sum(1 for r in rows if r["mismatch_flagged"]),
            "matched_expected": sum(
                1 for r in rows if r["decision"] == r["expected"]),
            "scenarios_with_score_change": len(moved),
            "max_score_drop": round(-min(deltas), 1) if deltas else 0.0,
            "max_score_rise": round(max(deltas), 1) if deltas else 0.0,
            # The pass criterion.
            "fail_closed_regressions": hardened,
            # The honest cost of failing open.
            "weakened_detections": weakened,
            "isolating_probes": probe_rows,
        })

    return {
        "generated_by": "evaluate_operator.py",
        "adapter_under_test": MockOperatorAdapter.name,
        "simulated": True,
        "note": "Operator integration in SIMShield is SIMULATED. These figures "
                "measure how the detection engine degrades when a simulated "
                "operator feed misbehaves; they are not measurements of any "
                "real telecom integration.",
        "criterion": "No scenario may become MORE restrictive because operator "
                     "data was degraded.",
        "pass": fail_closed_total == 0 and probe_regressions == 0,
        "fail_closed_regressions_total": fail_closed_total,
        "probe_fail_closed_total": probe_regressions,
        "baseline_distribution": _distribution(baseline),
        "probe_note": "The 40-scenario suite cannot measure this signal on its "
                      "own: its one operator-dependent case also fires eight "
                      "other flags whose raw points (305) already exceed the "
                      "behavioural cap (100), so removing the 65-point mismatch "
                      "flag changes nothing. The isolating probes supply the "
                      "measurable delta.",
        "conditions": conditions,
    }


def main():
    report = build_matrix()
    out = backend_path("data", "operator_degradation.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\nOPERATOR DEGRADATION MATRIX")
    print(f"adapter: {report['adapter_under_test']}  (simulated)")
    header = (f"{'condition':<20}{'ALLOW':>7}{'MONITOR':>9}{'VERIFY':>8}"
              f"{'BLOCK':>7}{'usable':>8}{'flagged':>9}{'max drop':>10}"
              f"{'max rise':>10}{'fail-closed':>13}")
    print("-" * len(header))
    print(header)
    print("-" * len(header))
    for c in report["conditions"]:
        d = c["decision_distribution"]
        print(f"{c['condition']:<20}{d['ALLOW']:>7}{d['MONITOR']:>9}"
              f"{d['VERIFY']:>8}{d['BLOCK']:>7}"
              f"{c['operator_usable_count']:>8}{c['mismatch_flagged_count']:>9}"
              f"{c['max_score_drop']:>10.1f}{c['max_score_rise']:>10.1f}"
              f"{len(c['fail_closed_regressions']):>13}")
    print("-" * len(header))

    print("\nISOLATING PROBES — the mismatch is the only elevated signal")
    phead = (f"{'condition':<20}{'probe':<44}{'decision':>10}"
             f"{'risk':>7}{'delta':>8}{'status':>22}")
    print("-" * len(phead))
    print(phead)
    print("-" * len(phead))
    for c in report["conditions"]:
        for p in c["isolating_probes"]:
            print(f"{c['condition']:<20}{p['probe'][:43]:<44}{p['decision']:>10}"
                  f"{p['risk_score']:>7.1f}{p['risk_delta_vs_available']:>+8.1f}"
                  f"{p['operator_status']:>22}")
    print("-" * len(phead))

    verdict = "PASS" if report["pass"] else "FAIL"
    print(f"\n{verdict}: {report['fail_closed_regressions_total']} scenario(s) "
          "became more restrictive under operator degradation (must be 0).")
    for c in report["conditions"]:
        if c["weakened_detections"]:
            print(f"\n  {c['condition']}: {len(c['weakened_detections'])} "
                  "detection(s) weakened (expected cost of failing open)")
            for w in c["weakened_detections"]:
                print(f"    - {w['scenario']}: {w['baseline']} -> {w['degraded']} "
                      f"({w['risk_delta']:+.1f} risk)")
    print(f"\nWritten to {out}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

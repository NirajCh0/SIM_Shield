"""
Drift and fairness monitoring report + self-validation (improvement #4).

Two halves, and the second is the one that matters academically.

LIVE REPORT
Runs `engine.monitoring.report()` against the real database and prints it. On a
prototype this will mostly say "insufficient data", and that is the correct
output — a fairness dashboard confidently rendering a disparity ratio over four
decisions would be worse than one that refuses.

SELF-VALIDATION
A monitor that never fires is indistinguishable from a monitor that is broken.
So this harness also feeds the PSI implementation distributions whose drift is
KNOWN by construction — identical, mildly shifted, heavily shifted — and checks
that it lands in the expected band. Likewise, the disparate-impact calculation
is fed a cohort split with a deliberate 3:1 disparity and must flag it, and an
even split which it must not.

That is the difference between "we built a fairness dashboard" and "we showed
the fairness dashboard detects unfairness".

Run:  python evaluate_monitoring.py
Writes data/monitoring_report.json.
"""
import json
import random

from engine import monitoring
from engine.config_loader import backend_path


def _validate_psi() -> list[dict]:
    """Feed PSI distributions whose drift is known, and check the verdict."""
    rng = random.Random(42)
    reference = [rng.gauss(20, 8) for _ in range(2000)]

    cases = [
        ("identical distribution", [rng.gauss(20, 8) for _ in range(2000)], "stable"),
        ("small shift (+2 mean)", [rng.gauss(22, 8) for _ in range(2000)],
         ("stable", "moderate shift")),
        ("large shift (+15 mean)", [rng.gauss(35, 8) for _ in range(2000)],
         "significant shift"),
        ("variance collapse", [rng.gauss(20, 1) for _ in range(2000)],
         "significant shift"),
    ]
    out = []
    for name, actual, expected in cases:
        psi = monitoring._psi(reference, actual)
        band = monitoring._band(psi)
        allowed = (expected,) if isinstance(expected, str) else expected
        out.append({"case": name, "psi": psi, "band": band,
                    "expected_band": list(allowed), "pass": band in allowed})
    return out


def _validate_disparate_impact() -> list[dict]:
    """A known-unfair split must flag; a fair one must not."""
    n = monitoring.MIN_COHORT_N + 20

    def rows(rate_a: float, rate_b: float) -> list[dict]:
        made = []
        for i in range(n):
            made.append({"region": "cohort_a",
                         "decision": "BLOCK" if i < rate_a * n else "ALLOW"})
            made.append({"region": "cohort_b",
                         "decision": "BLOCK" if i < rate_b * n else "ALLOW"})
        return made

    checks = []
    for name, a, b, should_flag in [
        ("even treatment (0.30 vs 0.30)", 0.30, 0.30, False),
        ("mild gap (0.30 vs 0.25)", 0.30, 0.25, False),
        ("3:1 disparity (0.60 vs 0.20)", 0.60, 0.20, True),
    ]:
        rates = monitoring._selection_rates(rows(a, b), "region")
        di = monitoring._disparate_impact(rates)
        checks.append({"case": name, "ratio": di["ratio"], "flagged": di["flag"],
                       "expected_flag": should_flag,
                       "pass": di["flag"] is should_flag})
    return checks


def _validate_sample_gate() -> list[dict]:
    """A cohort below the minimum must yield no rate at all."""
    small = [{"region": "tiny", "decision": "BLOCK"}] * 3
    rates = monitoring._selection_rates(small, "region")
    entry = rates["tiny"]
    di = monitoring._disparate_impact(rates)
    return [
        {"case": f"cohort of 3 (< {monitoring.MIN_COHORT_N})",
         "selection_rate": entry["selection_rate"], "sufficient": entry["sufficient"],
         "pass": entry["selection_rate"] is None and entry["sufficient"] is False},
        {"case": "disparate impact with one usable cohort",
         "ratio": di["ratio"], "flagged": di["flag"],
         "pass": di["ratio"] is None and di["flag"] is False},
    ]


def main():
    validation = {
        "psi": _validate_psi(),
        "disparate_impact": _validate_disparate_impact(),
        "sample_size_gate": _validate_sample_gate(),
    }
    all_checks = [c for group in validation.values() for c in group]
    passed = sum(1 for c in all_checks if c["pass"])

    report = {
        "generated_by": "evaluate_monitoring.py",
        "live": monitoring.report(),
        "self_validation": validation,
        "self_validation_passed": passed,
        "self_validation_total": len(all_checks),
        "pass": passed == len(all_checks),
        "note": "Cohort attributes are FICTIONAL (see engine/monitoring.py). The "
                "self-validation proves the monitors detect drift and disparity "
                "that is known by construction; the live section reports what "
                "this deployment actually has, including when that is too "
                "little to say anything.",
    }
    out = backend_path("data", "monitoring_report.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("\nMONITOR SELF-VALIDATION (drift and disparity known by construction)")
    print("-" * 78)
    for group, checks in validation.items():
        print(f"\n  {group}")
        for c in checks:
            mark = "OK  " if c["pass"] else "FAIL"
            detail = ", ".join(f"{k}={v}" for k, v in c.items()
                               if k not in ("case", "pass"))
            print(f"    {mark} {c['case']:<40} {detail}")
    print("-" * 78)
    print(f"{passed}/{len(all_checks)} self-validation checks passed")

    live = report["live"]
    print("\nLIVE REPORT (this deployment)")
    print("-" * 78)
    drift = live["drift"]["risk_score_psi"]
    print(f"  risk-score PSI      : {drift['psi']} ({drift['band']}) "
          f"[ref n={drift['reference_n']}, recent n={drift['recent_n']}]")
    fair = live["fairness"]
    print(f"  decisions analysed  : {fair['decisions_analysed']}")
    for dim, data in fair["dimensions"].items():
        di = data["disparate_impact"]
        print(f"  fairness/{dim:<12}: ratio={di['ratio']} flag={di['flag']} "
              f"({di['comparable_cohorts']} comparable cohorts)")
    fp = live["feedback"]["measured_false_positive_rate"]["overall"]
    print(f"  human-labelled FPR  : {fp['rate']} over {fp['total']} reviewed "
          f"(sufficient={fp['sufficient']})")
    print("-" * 78)
    print(f"\nWritten to {out}")
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())

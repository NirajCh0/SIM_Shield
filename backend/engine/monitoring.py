"""
Model drift and cohort fairness monitoring (improvement #4).

TWO QUESTIONS THIS ANSWERS
  1. **Drift** — is the traffic the detector sees today still the traffic it was
     tuned on? A model does not fail loudly; it fails by the world moving. PSI
     over the score distribution and the decision mix is the cheapest honest
     warning available.
  2. **Fairness** — does the detector restrict some groups more than others?
     The model card admits no fairness analysis was possible. This makes one
     possible, with the caveats stated below rather than buried.

READ THIS BEFORE QUOTING ANY FAIRNESS NUMBER
The cohort attributes are **FICTIONAL**. They live in `synthetic_cohort` on the
synthetic profiles and describe nobody; no demographic data is collected from
any real person, and none should be. What the analysis therefore measures is
whether the PIPELINE produces disparate outcomes across groups **as
constructed** — it is a demonstration that the measurement exists and works, not
a finding about Nepali subscribers.

Two things make this worth building anyway. First, a disparity here is still a
real property of the model given those inputs: if it restricts the "abroad"
cohort four times as often, that is the detector's behaviour, not the fixture's.
Second, the same code runs unchanged on real cohort data if a deployment ever
has a lawful basis for it — which is the point of writing it now.

SAMPLE SIZE IS ENFORCED, NOT SUGGESTED
Fifteen synthetic profiles cannot support a confident disparity ratio. Every
cohort below `MIN_COHORT_N` is reported with `sufficient: false` and a null
rate. A fairness dashboard that renders a bold "0.62 disparate impact" over
n=3 is worse than no dashboard, because someone will cite it.
"""
from __future__ import annotations

import json
import math

from . import db, profiles

#: A cohort smaller than this gets no rate. The four-fifths rule is a legal
#: heuristic designed for large samples; applying it to single digits produces
#: numbers that swing wildly on one case.
MIN_COHORT_N = 30

#: Below this, PSI is not reported at all.
MIN_PSI_N = 50

#: Standard PSI reading. These bands are the conventional credit-risk ones and
#: are heuristics, not thresholds with statistical meaning.
PSI_BANDS = ((0.10, "stable"), (0.25, "moderate shift"), (float("inf"), "significant shift"))

COHORT_DIMENSIONS = ("operator", "age_band", "region", "settlement")

#: Decisions that restrict the subscriber. The selection rate is computed over
#: these, because that is what "being treated differently" means in practice —
#: extra friction or a refused sign-in, not a score in a database.
RESTRICTIVE = ("VERIFY", "BLOCK")


# --- drift ---------------------------------------------------------------------
def _psi(expected: list[float], actual: list[float], buckets: int = 10) -> float | None:
    """
    Population Stability Index between two score distributions.

    Both sides are bucketed on the EXPECTED distribution's quantiles, which is
    the point: PSI asks how much of today's traffic has moved out of the bands
    the reference was built from.
    """
    if len(expected) < 10 or len(actual) < 10:
        return None
    ordered = sorted(expected)
    edges = [ordered[int(len(ordered) * i / buckets)] for i in range(1, buckets)]

    def distribute(values: list[float]) -> list[float]:
        counts = [0] * buckets
        for v in values:
            idx = 0
            while idx < len(edges) and v > edges[idx]:
                idx += 1
            counts[idx] += 1
        total = len(values) or 1
        # Floor at a small epsilon: an empty bucket makes the log term infinite,
        # which would report "infinite drift" for a bucket nobody landed in.
        return [max(c / total, 1e-4) for c in counts]

    exp_pct, act_pct = distribute(expected), distribute(actual)
    return round(sum((a - e) * math.log(a / e)
                     for e, a in zip(exp_pct, act_pct)), 4)


def _band(psi: float | None) -> str:
    if psi is None:
        return "insufficient data"
    for limit, label in PSI_BANDS:
        if psi < limit:
            return label
    return "significant shift"


def score_drift(reference_days: int = 30, recent_days: int = 7) -> dict:
    """
    PSI between an older reference window and recent scoring.

    Both windows come from `risk_history`, so this measures the drift the system
    has actually seen rather than a synthetic comparison.
    """
    reference = [r["score"] for r in db.query_all(
        "SELECT score FROM risk_history WHERE created_at < datetime('now', ?) "
        "AND created_at >= datetime('now', ?)",
        (f"-{recent_days} days", f"-{reference_days} days"))]
    recent = [r["score"] for r in db.query_all(
        "SELECT score FROM risk_history WHERE created_at >= datetime('now', ?)",
        (f"-{recent_days} days",))]

    psi = _psi(reference, recent)
    sufficient = len(reference) >= MIN_PSI_N and len(recent) >= MIN_PSI_N
    return {
        "reference_n": len(reference),
        "recent_n": len(recent),
        "reference_window_days": reference_days,
        "recent_window_days": recent_days,
        "psi": psi if sufficient else None,
        "band": _band(psi) if sufficient else "insufficient data",
        "sufficient": sufficient,
        "note": None if sufficient else
                f"Needs at least {MIN_PSI_N} scores in each window; have "
                f"{len(reference)} reference and {len(recent)} recent.",
    }


def decision_mix_drift(reference_days: int = 30, recent_days: int = 7) -> dict:
    """
    Has the mix of ALLOW/MONITOR/VERIFY/BLOCK shifted?

    This is the drift signal a fraud desk feels first — the queue gets longer —
    and it needs no model internals, so it keeps working if the model is swapped.
    """
    def mix(where: str, params: tuple) -> dict:
        rows = db.query_all(
            "SELECT json_extract(meta,'$.decision') AS decision, COUNT(*) AS n "
            f"FROM activity_log WHERE action='pre_otp_check' AND {where} "
            "GROUP BY decision", params)
        total = sum(r["n"] for r in rows) or 0
        return {"total": total,
                "share": {r["decision"]: round(r["n"] / total, 4)
                          for r in rows if r["decision"]} if total else {}}

    reference = mix("created_at < datetime('now', ?) AND created_at >= datetime('now', ?)",
                    (f"-{recent_days} days", f"-{reference_days} days"))
    recent = mix("created_at >= datetime('now', ?)", (f"-{recent_days} days",))

    deltas = {}
    for decision in ("ALLOW", "MONITOR", "VERIFY", "BLOCK"):
        before = reference["share"].get(decision, 0.0)
        after = recent["share"].get(decision, 0.0)
        deltas[decision] = round(after - before, 4)
    sufficient = reference["total"] >= MIN_PSI_N and recent["total"] >= MIN_PSI_N
    return {"reference": reference, "recent": recent,
            "share_delta": deltas if sufficient else None,
            "sufficient": sufficient,
            "note": None if sufficient else
                    "Not enough scored logins in both windows to compare."}


# --- fairness ------------------------------------------------------------------
def _cohort_of(profile_id: str | None) -> dict:
    """The fictional cohort attributes for a linked synthetic profile."""
    blank = {d: "unknown" for d in COHORT_DIMENSIONS}
    if not profile_id:
        return blank
    profile = profiles.load(profile_id)
    if not profile:
        return blank
    cohort = profile.get("synthetic_cohort") or {}
    return {
        "operator": profile.get("operator") or "unknown",
        "age_band": cohort.get("age_band", "unknown"),
        "region": cohort.get("region", "unknown"),
        "settlement": cohort.get("settlement", "unknown"),
    }


def _scored_decisions(days: int) -> list[dict]:
    """Every pre-OTP decision in the window, joined to its subscriber's cohort."""
    rows = db.query_all(
        "SELECT a.user_id, a.meta, u.profile_id FROM activity_log a "
        "LEFT JOIN users u ON u.id = a.user_id "
        "WHERE a.action = 'pre_otp_check' AND a.created_at >= datetime('now', ?)",
        (f"-{days} days",))
    out = []
    cache: dict = {}
    for r in rows:
        try:
            meta = json.loads(r["meta"] or "{}")
        except ValueError:
            continue
        decision = meta.get("decision")
        if not decision:
            continue
        pid = r["profile_id"]
        if pid not in cache:
            cache[pid] = _cohort_of(pid)
        out.append({"decision": decision, "risk": meta.get("risk"),
                    "user_id": r["user_id"], **cache[pid]})
    return out


def _selection_rates(rows: list[dict], dimension: str) -> dict:
    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(r.get(dimension, "unknown"), []).append(r)

    out = {}
    for name, members in sorted(groups.items()):
        n = len(members)
        restricted = sum(1 for m in members if m["decision"] in RESTRICTIVE)
        sufficient = n >= MIN_COHORT_N
        out[name] = {
            "n": n,
            "restricted": restricted,
            "selection_rate": round(restricted / n, 4) if sufficient else None,
            "sufficient": sufficient,
        }
    return out


def _disparate_impact(rates: dict) -> dict:
    """
    Ratio of the lowest to the highest selection rate across cohorts that have
    enough data — the four-fifths rule. Below 0.8 is the conventional flag.

    Cohorts without enough data are EXCLUDED, not treated as zero. Including
    them would let a small group with no restrictions manufacture a reassuring
    ratio out of nothing.
    """
    usable = {k: v["selection_rate"] for k, v in rates.items()
              if v["sufficient"] and v["selection_rate"] is not None}
    if len(usable) < 2:
        return {"ratio": None, "flag": False, "comparable_cohorts": len(usable),
                "note": f"Needs at least two cohorts with {MIN_COHORT_N}+ "
                        "decisions to compare."}
    highest = max(usable.values())
    lowest = min(usable.values())
    if highest == 0:
        return {"ratio": None, "flag": False, "comparable_cohorts": len(usable),
                "note": "No cohort was restricted at all in this window."}
    ratio = round(lowest / highest, 4)
    return {
        "ratio": ratio,
        "flag": ratio < 0.8,
        "comparable_cohorts": len(usable),
        "most_restricted": max(usable, key=usable.get),
        "least_restricted": min(usable, key=usable.get),
        "note": "Four-fifths rule: a ratio under 0.8 conventionally indicates "
                "disparate impact and warrants investigation, not an automatic "
                "conclusion of unfairness.",
    }


def _upheld_appeals_by_cohort(dimension: str, days: int) -> dict:
    """
    Where are the human-confirmed mistakes falling?

    This is the strongest fairness signal available, because the label came from
    an analyst rather than from the model. It is also the sparsest.
    """
    rows = db.query_all(
        "SELECT ap.status, u.profile_id FROM appeals ap "
        "LEFT JOIN users u ON u.id = ap.user_id "
        "WHERE ap.created_at >= datetime('now', ?)", (f"-{days} days",))
    groups: dict[str, dict] = {}
    for r in rows:
        cohort = _cohort_of(r["profile_id"]).get(dimension, "unknown")
        entry = groups.setdefault(cohort, {"appeals": 0, "upheld": 0})
        entry["appeals"] += 1
        if r["status"] == "upheld":
            entry["upheld"] += 1
    return groups


def fairness(days: int = 30) -> dict:
    rows = _scored_decisions(days)
    dimensions = {}
    for dimension in COHORT_DIMENSIONS:
        rates = _selection_rates(rows, dimension)
        dimensions[dimension] = {
            "cohorts": rates,
            "disparate_impact": _disparate_impact(rates),
            "upheld_appeals": _upheld_appeals_by_cohort(dimension, days),
        }
    return {
        "window_days": days,
        "decisions_analysed": len(rows),
        "min_cohort_n": MIN_COHORT_N,
        "dimensions": dimensions,
        "synthetic_cohorts": True,
        "warning": "Cohort attributes are FICTIONAL, attached to synthetic "
                   "profiles for demonstration. No demographic data is "
                   "collected from any real person. These figures show that the "
                   "measurement works; they are NOT findings about real "
                   "subscribers and must never be presented as such.",
    }


def report(days: int = 30) -> dict:
    from . import feedback
    return {
        "generated_at": db.now(),
        "drift": {
            "risk_score_psi": score_drift(),
            "decision_mix": decision_mix_drift(),
            "psi_bands": {"stable": "< 0.10", "moderate shift": "0.10 – 0.25",
                          "significant shift": "> 0.25"},
        },
        "fairness": fairness(days),
        "feedback": feedback.report(),
        "honest_summary": "Drift and fairness monitoring exist and are wired to "
                          "real system data, but a prototype with a handful of "
                          "accounts cannot produce statistically meaningful "
                          "values. Every rate here carries its own denominator "
                          "and a `sufficient` flag; respect them.",
    }

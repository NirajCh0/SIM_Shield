"""
Outcome feedback: the false-positive rate measured from human labels.

WHY THIS IS DIFFERENT FROM THE FIGURE IN THE MODEL CARD
`evaluate_ml.py` reports FPR = 1.8%. That is measured against the labels the
synthetic dataset shipped with — the model is being marked by the same process
that wrote its exam. It is a valid statement about internal consistency and a
worthless one about reality.

This module measures something else: of the restrictive decisions a human
actually reviewed, how many did that human code as having stopped a genuine
subscriber. The label comes from a person examining evidence, not from the
generator.

READ THE CAVEATS BEFORE QUOTING ANY NUMBER FROM HERE
  * The denominator is REVIEWED decisions, not all decisions. Only a fraction of
    decisions are ever appealed or investigated.
  * Appeals are self-selected. People who are wrongly stopped and give up are
    invisible, so this is a LOWER bound on the true false-positive burden.
  * A prototype produces tens of labels, not thousands. `sufficient` is False
    below the threshold, and every consumer must respect it rather than
    rendering a confident percentage over n=4.

Reporting a badly-founded number confidently is worse than reporting no number,
so every figure here ships with its own denominator and a sufficiency flag.
"""
from __future__ import annotations

import math

from . import cases, db

#: Below this many reviewed outcomes, rates are reported as `null` with
#: `sufficient: false`. Chosen so a single case cannot swing a headline figure
#: by tens of percentage points.
MIN_REVIEWED = 20


def _fp_codes() -> set[str]:
    return {c["code"] for c in cases.taxonomy()["codes"]
            if c.get("counts_as_false_positive")}


def _wilson(successes: int, total: int, z: float = 1.96) -> tuple[float, float]:
    """
    Wilson score interval. Used instead of the normal approximation because at
    these sample sizes the naive interval produces bounds below 0 or above 1,
    which would look precise and be nonsense.
    """
    if total == 0:
        return (0.0, 1.0)
    p = successes / total
    denom = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denom
    margin = (z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total))) / denom
    return (max(0.0, centre - margin), min(1.0, centre + margin))


def _rate(successes: int, total: int) -> dict:
    """
    A rate with its own denominator, or no rate at all.

    Below `MIN_REVIEWED` the `rate` and `ci95` fields are **null**, not merely
    accompanied by a warning flag. A number that is present gets read, quoted
    and put in a table no matter what caveat sits beside it; the only reliable
    way to stop "100% false positives (n=3)" reaching a slide is to not emit
    the figure. The raw counts stay, because those are honest at any size.
    """
    sufficient = total >= MIN_REVIEWED
    low, high = _wilson(successes, total)
    return {
        "count": successes,
        "total": total,
        "rate": round(successes / total, 4) if sufficient else None,
        "ci95": [round(low, 4), round(high, 4)] if sufficient else None,
        "sufficient": sufficient,
        "note": None if sufficient else
                f"Only {total} reviewed outcome(s); at least {MIN_REVIEWED} are "
                "needed before this rate means anything.",
    }


def outcome_counts() -> dict:
    rows = db.query_all(
        "SELECT outcome, reason_code, COUNT(*) AS n FROM cases "
        "WHERE outcome IS NOT NULL GROUP BY outcome, reason_code")
    by_outcome: dict[str, int] = {}
    by_code: dict[str, int] = {}
    for r in rows:
        by_outcome[r["outcome"]] = by_outcome.get(r["outcome"], 0) + r["n"]
        by_code[r["reason_code"]] = r["n"]
    return {"by_outcome": by_outcome, "by_reason_code": by_code}


def measured_false_positive_rate() -> dict:
    """
    Human-labelled FPR over reviewed restrictive decisions.

    `inconclusive` and `duplicate` outcomes are excluded from the denominator
    entirely. Counting "we could not tell" as a correct decision would flatter
    the detector, and counting it as an error would do the opposite; neither is
    a finding, so they are removed and reported separately.
    """
    fp_codes = _fp_codes()
    rows = db.query_all(
        "SELECT reason_code, outcome, decision FROM cases "
        "WHERE outcome IS NOT NULL AND decision IS NOT NULL")
    decided = [r for r in rows if r["outcome"] not in ("inconclusive", "duplicate")]
    restrictive = [r for r in decided if r["decision"] in ("VERIFY", "BLOCK")]
    fps = [r for r in restrictive if r["reason_code"] in fp_codes]

    per_decision = {}
    for decision in ("MONITOR", "VERIFY", "BLOCK"):
        band = [r for r in decided if r["decision"] == decision]
        hits = [r for r in band if r["reason_code"] in fp_codes]
        per_decision[decision] = _rate(len(hits), len(band))

    excluded = len(rows) - len(decided)
    return {
        "overall": _rate(len(fps), len(restrictive)),
        "per_decision": per_decision,
        "excluded_inconclusive_or_duplicate": excluded,
        "label_source": "analyst-coded case outcomes (reason_codes.yaml)",
        "caveats": [
            "Denominator is REVIEWED decisions only, not all decisions.",
            "Appeals are self-selected, so this is a lower bound on the true "
            "false-positive burden — people who give up are invisible.",
            "Not comparable with the 1.8% in the model card: that figure is "
            "measured against synthetic labels from the dataset generator, "
            "this one against human review of specific decisions.",
        ],
    }


def appeal_stats() -> dict:
    rows = db.query_all("SELECT status, COUNT(*) AS n FROM appeals GROUP BY status")
    by_status = {r["status"]: r["n"] for r in rows}
    answered = by_status.get("upheld", 0) + by_status.get("rejected", 0)
    upheld = by_status.get("upheld", 0)

    times = db.query_all(
        "SELECT created_at, resolved_at FROM appeals WHERE resolved_at IS NOT NULL")
    hours = []
    for r in times:
        try:
            from datetime import datetime
            hours.append((datetime.fromisoformat(r["resolved_at"])
                          - datetime.fromisoformat(r["created_at"])).total_seconds() / 3600)
        except (TypeError, ValueError):
            continue
    return {
        "by_status": by_status,
        "answered": answered,
        "uphold_rate": _rate(upheld, answered),
        "pending": by_status.get("submitted", 0) + by_status.get("reviewing", 0),
        "mean_hours_to_answer": round(sum(hours) / len(hours), 2) if hours else None,
    }


def report() -> dict:
    """Everything the loop produces, for the admin dashboard and the thesis."""
    return {
        "measured_false_positive_rate": measured_false_positive_rate(),
        "appeals": appeal_stats(),
        "outcomes": outcome_counts(),
        "min_reviewed_for_significance": MIN_REVIEWED,
        "what_this_is": "False-positive rate derived from HUMAN-CODED case "
                        "outcomes, not from the synthetic dataset labels. It is "
                        "the only accuracy figure in this project whose ground "
                        "truth does not come from the process being evaluated.",
    }

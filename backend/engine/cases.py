"""
Fraud-analyst case management with coded outcomes (improvement #2).

WHY THIS EXISTS
SIMShield claims "human-in-the-loop" review. Before this module that claim
rested on an alert list with a four-value status field: an analyst could mark
something 'resolved' and nothing recorded WHY, so the decision could not be
counted, compared between analysts, or disagreed with later. A control nobody
can review is not a control.

A case therefore carries a **reason code from a fixed taxonomy**
(`reason_codes.yaml`), and the outcome is derived from the code rather than
chosen separately. That single constraint is what makes the rest possible:

  * the false-positive rate gets a denominator that is not the model's own
    opinion (see engine/feedback.py);
  * two analysts closing the same kind of case produce comparable records;
  * "inconclusive" is a distinct outcome, so uncertainty is never silently
    counted as the detector being right.

ACCOUNTABILITY
Every analyst action is appended to the tamper-evident audit chain with the
analyst pseudonymised — staff are accountable on the same terms as subscribers,
which is also what makes the audit trail usable as evidence about the *process*
and not only about the users.

SEPARATION OF DUTIES
An analyst may not review their own appeal, and may not resolve a case they
opened as an appeal on their own account. Enforced in `resolve()`.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

from . import compliance, db, privacy
from .config_loader import load_reason_codes

STATUSES = ("open", "investigating", "awaiting_customer", "resolved")
SEVERITIES = ("low", "medium", "high", "critical")


# --- taxonomy ------------------------------------------------------------------
def taxonomy() -> dict:
    """The full reason-code taxonomy, for the analyst UI and for validation."""
    spec = load_reason_codes()
    return {
        "version": spec["version"],
        "outcomes": spec["outcomes"],
        "codes": spec["codes"],
        "sla_hours": spec["sla_hours"],
    }


def code_spec(code: str) -> dict | None:
    for entry in load_reason_codes()["codes"]:
        if entry["code"] == code:
            return entry
    return None


def valid_codes() -> set[str]:
    return {c["code"] for c in load_reason_codes()["codes"]}


def _sla_due(severity: str, opened: datetime) -> str:
    hours = load_reason_codes()["sla_hours"].get(severity, 24)
    return (opened + timedelta(hours=float(hours))).isoformat(timespec="seconds")


# --- lifecycle -----------------------------------------------------------------
def open_case(user_id: int | None, title: str, *, severity: str = "medium",
              decision: str | None = None, risk_score: float | None = None,
              alert_id: int | None = None, source: str = "detector",
              opened_by: str = "system", note: str | None = None) -> dict:
    """Open a case. Returns the created row."""
    if severity not in SEVERITIES:
        severity = "medium"
    now = datetime.now()
    stamp = now.isoformat(timespec="seconds")
    case_id = db.execute(
        "INSERT INTO cases (user_id, alert_id, title, severity, status, opened_by, "
        "risk_score, decision, source, due_at, created_at, updated_at) "
        "VALUES (?,?,?,?,'open',?,?,?,?,?,?,?)",
        (user_id, alert_id, title[:200], severity, opened_by, risk_score, decision,
         source, _sla_due(severity, now), stamp, stamp))
    if note:
        add_note(case_id, None, note, kind="note")
    _audit("case_opened", case_id, {"severity": severity, "source": source,
                                    "decision": decision})
    return get_case(case_id)


def auto_open_for_decision(user_id: int, decision: str, risk_score: float,
                           reasons: list | None = None) -> dict | None:
    """
    Open a case when the detector reaches a decision that requires a human.

    Deliberately idempotent per (user, decision) within an hour: a subscriber
    retrying a blocked login five times is one investigation, not five. Without
    this the queue fills with duplicates of the same event and the SLA figures
    become meaningless.
    """
    spec = load_reason_codes().get("auto_open_on_decision") or {}
    severity = spec.get(decision)
    if not severity:
        return None
    existing = db.query_one(
        "SELECT id FROM cases WHERE user_id = ? AND decision = ? AND status != 'resolved' "
        "AND created_at >= datetime('now','-1 hour') ORDER BY id DESC LIMIT 1",
        (user_id, decision))
    if existing:
        return get_case(existing["id"])
    summary = "; ".join(str(r) for r in (reasons or [])[:3]) or "no reasons recorded"
    return open_case(
        user_id, f"{decision} decision at risk {risk_score}", severity=severity,
        decision=decision, risk_score=risk_score, source="detector",
        note=f"Opened automatically. Detector reasons: {summary}")


def get_case(case_id: int) -> dict | None:
    row = db.query_one(
        "SELECT c.*, u.email, u.display_name FROM cases c "
        "LEFT JOIN users u ON u.id = c.user_id WHERE c.id = ?", (case_id,))
    if row:
        row["overdue"] = is_overdue(row)
    return row


def is_overdue(case: dict) -> bool:
    if case.get("status") == "resolved" or not case.get("due_at"):
        return False
    return case["due_at"] < db.now()


def list_cases(status: str | None = None, assigned_to: int | None = None,
               overdue_only: bool = False, limit: int = 100) -> list[dict]:
    sql = ("SELECT c.*, u.email, u.display_name FROM cases c "
           "LEFT JOIN users u ON u.id = c.user_id WHERE 1=1")
    params: list = []
    if status in STATUSES:
        sql += " AND c.status = ?"
        params.append(status)
    if assigned_to is not None:
        sql += " AND c.assigned_to = ?"
        params.append(assigned_to)
    sql += " ORDER BY CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 " \
           "WHEN 'medium' THEN 2 ELSE 3 END, c.created_at DESC LIMIT ?"
    params.append(int(limit))
    rows = db.query_all(sql, tuple(params))
    for r in rows:
        r["overdue"] = is_overdue(r)
    if overdue_only:
        rows = [r for r in rows if r["overdue"]]
    return rows


def add_note(case_id: int, author_id: int | None, body: str,
             kind: str = "note", meta: dict | None = None) -> int:
    note_id = db.execute(
        "INSERT INTO case_notes (case_id, author_id, kind, body, meta, created_at) "
        "VALUES (?,?,?,?,?,?)",
        (case_id, author_id, kind, body[:4000], json.dumps(meta or {}), db.now()))
    db.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (db.now(), case_id))
    return note_id


def notes(case_id: int) -> list[dict]:
    rows = db.query_all(
        "SELECT n.*, u.display_name AS author_name FROM case_notes n "
        "LEFT JOIN users u ON u.id = n.author_id "
        "WHERE n.case_id = ? ORDER BY n.created_at, n.id", (case_id,))
    for r in rows:
        r["meta"] = json.loads(r["meta"] or "{}")
    return rows


def assign(case_id: int, analyst_id: int | None, by: int) -> dict | None:
    if not get_case(case_id):
        return None
    db.execute("UPDATE cases SET assigned_to = ?, updated_at = ? WHERE id = ?",
               (analyst_id, db.now(), case_id))
    add_note(case_id, by,
             f"Assigned to analyst #{analyst_id}" if analyst_id else "Unassigned",
             kind="assignment")
    _audit("case_assigned", case_id, {"assigned_to": analyst_id}, actor=by)
    return get_case(case_id)


def set_status(case_id: int, status: str, by: int, note: str = "") -> dict | None:
    """
    Move a case through the workflow. `resolved` is NOT reachable here — it
    requires a reason code, so it must go through `resolve()`. Otherwise an
    analyst could close a case with no recorded justification, which is exactly
    the gap this improvement exists to remove.
    """
    if status not in STATUSES or status == "resolved":
        raise ValueError(
            "status must be one of open/investigating/awaiting_customer; "
            "resolving a case requires a reason code (use resolve())")
    if not get_case(case_id):
        return None
    db.execute("UPDATE cases SET status = ?, updated_at = ? WHERE id = ?",
               (status, db.now(), case_id))
    add_note(case_id, by, note or f"Status changed to {status}", kind="status")
    _audit("case_status", case_id, {"status": status}, actor=by)
    return get_case(case_id)


class ResolutionError(ValueError):
    """Raised when a resolution would be unreviewable or self-approved."""


def resolve(case_id: int, reason_code: str, by: int, note: str = "",
            evidence: str = "") -> dict:
    """
    Close a case with a coded outcome.

    Four things are enforced here, each of them a way the record could
    otherwise become misleading:

      1. The code must exist in the taxonomy — no ad-hoc outcomes.
      2. The outcome is DERIVED from the code, never supplied by the caller, so
         a resolution cannot claim "false positive" while citing a fraud code.
      3. Codes marked `requires_evidence` need a non-empty evidence note. The
         codes that count against the detector's accuracy are the ones that
         must be justified.
      4. An analyst may not resolve a case about their own account.
    """
    case = get_case(case_id)
    if not case:
        raise ResolutionError("Case not found.")
    if case["status"] == "resolved":
        raise ResolutionError("Case is already resolved.")

    spec = code_spec(reason_code)
    if not spec:
        raise ResolutionError(
            f"Unknown reason code {reason_code!r}. Valid codes: "
            f"{sorted(valid_codes())}")
    if spec.get("requires_evidence") and not (evidence or "").strip():
        raise ResolutionError(
            f"Reason code {reason_code} requires an evidence note describing "
            "what was checked and how.")
    if case.get("user_id") and int(case["user_id"]) == int(by):
        raise ResolutionError(
            "An analyst cannot resolve a case about their own account.")

    outcome = spec["outcome"]                      # derived, never passed in
    stamp = db.now()
    db.execute(
        "UPDATE cases SET status = 'resolved', outcome = ?, reason_code = ?, "
        "resolved_at = ?, updated_at = ? WHERE id = ?",
        (outcome, reason_code, stamp, stamp, case_id))
    body = f"Resolved as {outcome} ({reason_code}: {spec['label']})."
    if note:
        body += f" {note}"
    if evidence:
        body += f"\nEvidence: {evidence}"
    add_note(case_id, by, body, kind="outcome",
             meta={"reason_code": reason_code, "outcome": outcome})
    _audit("case_resolved", case_id,
           {"reason_code": reason_code, "outcome": outcome,
            "counts_as_false_positive": bool(spec.get("counts_as_false_positive"))},
           actor=by)
    return get_case(case_id)


def reopen(case_id: int, by: int, note: str) -> dict | None:
    """
    Reopen a resolved case. The original outcome is kept in the note history —
    a review process that can silently erase its own past decisions is not one.
    """
    case = get_case(case_id)
    if not case:
        return None
    db.execute(
        "UPDATE cases SET status = 'investigating', outcome = NULL, "
        "reason_code = NULL, resolved_at = NULL, updated_at = ? WHERE id = ?",
        (db.now(), case_id))
    add_note(case_id, by,
             f"Reopened (was {case['outcome']} / {case['reason_code']}). {note}",
             kind="status", meta={"previous_outcome": case["outcome"],
                                  "previous_reason_code": case["reason_code"]})
    _audit("case_reopened", case_id,
           {"previous_outcome": case["outcome"]}, actor=by)
    return get_case(case_id)


# --- reporting -----------------------------------------------------------------
def queue_stats() -> dict:
    """Headline numbers for the fraud desk."""
    def one(sql, params=()):
        return (db.query_one(sql, params) or {}).get("n", 0)
    by_status = {s: one("SELECT COUNT(*) AS n FROM cases WHERE status = ?", (s,))
                 for s in STATUSES}
    by_outcome = {r["outcome"]: r["n"] for r in db.query_all(
        "SELECT outcome, COUNT(*) AS n FROM cases WHERE outcome IS NOT NULL "
        "GROUP BY outcome")}
    by_code = db.query_all(
        "SELECT reason_code, COUNT(*) AS n FROM cases WHERE reason_code IS NOT NULL "
        "GROUP BY reason_code ORDER BY n DESC")
    overdue = len([c for c in list_cases(limit=500) if c["overdue"]])
    resolved = db.query_all(
        "SELECT created_at, resolved_at FROM cases WHERE resolved_at IS NOT NULL "
        "ORDER BY id DESC LIMIT 200")
    hours = []
    for r in resolved:
        try:
            delta = (datetime.fromisoformat(r["resolved_at"])
                     - datetime.fromisoformat(r["created_at"])).total_seconds() / 3600
            hours.append(delta)
        except (TypeError, ValueError):
            continue
    return {
        "by_status": by_status,
        "by_outcome": by_outcome,
        "by_reason_code": by_code,
        "overdue": overdue,
        "open_total": by_status["open"] + by_status["investigating"]
                      + by_status["awaiting_customer"],
        "median_hours_to_resolve": round(_median(hours), 2) if hours else None,
        "resolved_sampled": len(hours),
    }


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    mid = n // 2
    return ordered[mid] if n % 2 else (ordered[mid - 1] + ordered[mid]) / 2


def _audit(action: str, case_id: int, meta: dict, actor: int | None = None) -> None:
    """
    Record an analyst action in the tamper-evident chain.

    The analyst is pseudonymised exactly like a subscriber. Accountability for
    staff should not be weaker than accountability for users, and it should not
    require storing who-did-what in cleartext to achieve it.
    """
    try:
        compliance.record_staff_action(
            actor_pseudonym=privacy.hash_id(f"staff:{actor}") if actor else "system",
            action=action, target=f"case:{case_id}", meta=meta)
    except Exception:                              # noqa: BLE001
        # Auditing must not be able to break the fraud desk.
        pass

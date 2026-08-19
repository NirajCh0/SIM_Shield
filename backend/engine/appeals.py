"""
Subscriber appeals — the false-positive feedback loop (improvement #3).

WHY THIS EXISTS
The evaluation reports a false-positive rate of 1.8%. That number comes
entirely from synthetic labels: the model is being marked against the same
generator that produced its training data. Nothing in the system let the person
who was actually stopped say "that was me, and you were wrong".

An appeal is that channel, and an analyst's coded resolution turns it into a
LABEL the system did not generate itself. `engine/feedback.py` then measures the
false-positive rate against those labels. It is a small number of labels in a
prototype, but it is the only measurement in this project whose ground truth
does not come from the same process being evaluated.

FAIRNESS, NOT JUST ACCURACY
A detector that stops a migrant worker signing in from Doha is not making a
random error — it is making a *patterned* one, against a group who cannot easily
walk into a branch. Appeals make that pattern visible: `engine/monitoring.py`
breaks upheld appeals down by cohort, so a disparity shows up as evidence rather
than as an anecdote.

PRIVACY
An appeal contains the subscriber's own words and is personal data. The stored
context is minimised through `privacy.minimise_attempt` — decision, score and
coarse area only, never coordinates — and the whole record falls under a
retention window in compliance.yaml.
"""
from __future__ import annotations

import json

from . import cases, compliance, db, privacy
from .config_loader import load_compliance

STATUSES = ("submitted", "reviewing", "upheld", "rejected", "withdrawn")

#: Appeals a subscriber may file in this window, to stop the queue being
#: flooded — by a frustrated user or by someone hoping a tired analyst
#: eventually waves a fraudulent session through.
MAX_OPEN_PER_USER = 3

#: An appeal is only meaningful about a decision that actually restricted
#: someone. Appealing an ALLOW is not a false positive by any definition.
APPEALABLE = ("MONITOR", "VERIFY", "BLOCK")


class AppealError(ValueError):
    """Raised when an appeal cannot be accepted or reviewed as requested."""


def _retention_days() -> int:
    return int(load_compliance()["retention"].get("appeal_days", 365))


def submit(user: dict, statement: str, decision: str | None = None,
           risk_score: float | None = None, context: dict | None = None) -> dict:
    """
    File an appeal against a restrictive decision.

    Opens a linked case so the appeal lands in the same reviewed queue as
    detector-raised work, rather than in a side channel nobody watches.
    """
    statement = (statement or "").strip()
    if len(statement) < 10:
        raise AppealError(
            "Please describe what happened in at least a sentence — an analyst "
            "needs something to check.")
    if len(statement) > 4000:
        raise AppealError("Please keep your description under 4000 characters.")

    if decision and decision not in APPEALABLE:
        raise AppealError(
            f"Only {', '.join(APPEALABLE)} decisions can be appealed; "
            f"{decision} did not restrict your account.")

    open_count = (db.query_one(
        "SELECT COUNT(*) AS n FROM appeals WHERE user_id = ? "
        "AND status IN ('submitted','reviewing')", (user["id"],)) or {}).get("n", 0)
    if open_count >= MAX_OPEN_PER_USER:
        raise AppealError(
            f"You already have {open_count} appeals awaiting review. Please wait "
            "for those to be answered before filing another.")

    # Minimise before storing: an appeal must not become a place where the raw
    # location we deliberately dropped after scoring comes back.
    safe_context = privacy.minimise_attempt({
        **(context or {}), "decision": decision, "risk_score": risk_score})

    case = cases.open_case(
        user["id"], f"Appeal: {decision or 'decision'} disputed by subscriber",
        severity="high" if decision == "BLOCK" else "medium",
        decision=decision, risk_score=risk_score, source="appeal",
        opened_by="subscriber",
        note="Subscriber disputes this decision. Their statement is attached to "
             "the appeal record.")

    appeal_id = db.execute(
        "INSERT INTO appeals (user_id, case_id, decision, risk_score, context, "
        "statement, status, created_at) VALUES (?,?,?,?,?,?, 'submitted', ?)",
        (user["id"], case["id"], decision, risk_score, json.dumps(safe_context),
         statement, db.now()))
    cases.add_note(case["id"], user["id"],
                   f"Subscriber statement: {statement}", kind="appeal",
                   meta={"appeal_id": appeal_id})
    db.log_activity(user["id"], "appeal_submitted",
                    {"appeal_id": appeal_id, "decision": decision})
    compliance.record_staff_action(
        actor_pseudonym=privacy.hash_id(f"subscriber:{user['id']}"),
        action="appeal_submitted", target=f"appeal:{appeal_id}",
        meta={"decision": decision, "case_id": case["id"]})
    return get(appeal_id)


def get(appeal_id: int) -> dict | None:
    row = db.query_one(
        "SELECT a.*, u.email, u.display_name FROM appeals a "
        "LEFT JOIN users u ON u.id = a.user_id WHERE a.id = ?", (appeal_id,))
    if row:
        row["context"] = json.loads(row["context"] or "{}")
    return row


def list_for_user(user_id: int, limit: int = 25) -> list[dict]:
    rows = db.query_all(
        "SELECT id, case_id, decision, risk_score, statement, status, "
        "outcome_note, created_at, resolved_at FROM appeals WHERE user_id = ? "
        "ORDER BY id DESC LIMIT ?", (user_id, int(limit)))
    return rows


def list_queue(status: str | None = None, limit: int = 100) -> list[dict]:
    sql = ("SELECT a.*, u.email, u.display_name FROM appeals a "
           "LEFT JOIN users u ON u.id = a.user_id")
    params: tuple = ()
    if status in STATUSES:
        sql += " WHERE a.status = ?"
        params = (status,)
    sql += " ORDER BY CASE a.status WHEN 'submitted' THEN 0 WHEN 'reviewing' " \
           "THEN 1 ELSE 2 END, a.created_at LIMIT ?"
    rows = db.query_all(sql, params + (int(limit),))
    for r in rows:
        r["context"] = json.loads(r["context"] or "{}")
    return rows


def withdraw(appeal_id: int, user_id: int) -> dict:
    appeal = get(appeal_id)
    if not appeal or appeal["user_id"] != user_id:
        raise AppealError("Appeal not found.")
    if appeal["status"] not in ("submitted", "reviewing"):
        raise AppealError("This appeal has already been answered.")
    db.execute("UPDATE appeals SET status = 'withdrawn', resolved_at = ? WHERE id = ?",
               (db.now(), appeal_id))
    if appeal["case_id"]:
        cases.add_note(appeal["case_id"], user_id,
                       "Subscriber withdrew the appeal.", kind="appeal")
    return get(appeal_id)


def review(appeal_id: int, analyst_id: int, uphold: bool, reason_code: str,
           note: str = "", evidence: str = "") -> dict:
    """
    Decide an appeal, and resolve its case with the same coded outcome.

    `uphold=True` means the SUBSCRIBER was right and the system was wrong, so
    the reason code must be one that counts as a false positive. Refusing the
    mismatch is the point: an analyst cannot record a sympathetic-sounding
    "upheld" while citing a code that keeps the detector's accuracy intact.
    Nor can they reject an appeal while citing a false-positive code.
    """
    appeal = get(appeal_id)
    if not appeal:
        raise AppealError("Appeal not found.")
    if appeal["status"] in ("upheld", "rejected", "withdrawn"):
        raise AppealError("This appeal has already been answered.")
    if int(appeal["user_id"]) == int(analyst_id):
        raise AppealError("An analyst cannot review their own appeal.")

    spec = cases.code_spec(reason_code)
    if not spec:
        raise AppealError(f"Unknown reason code {reason_code!r}.")
    counts_fp = bool(spec.get("counts_as_false_positive"))
    if uphold and not counts_fp:
        raise AppealError(
            f"Upholding an appeal means the decision was wrong, but {reason_code} "
            f"({spec['label']}) is not a false-positive code. Either pick an FP "
            "code or reject the appeal.")
    if not uphold and counts_fp:
        raise AppealError(
            f"{reason_code} ({spec['label']}) records a false positive, which "
            "means the subscriber was right. Uphold the appeal instead of "
            "rejecting it.")

    status = "upheld" if uphold else "rejected"
    db.execute(
        "UPDATE appeals SET status = ?, outcome_note = ?, reviewed_by = ?, "
        "resolved_at = ? WHERE id = ?",
        (status, note[:2000], analyst_id, db.now(), appeal_id))

    if appeal["case_id"]:
        try:
            cases.resolve(appeal["case_id"], reason_code, analyst_id,
                          note=f"Appeal {status}. {note}", evidence=evidence)
        except cases.ResolutionError as exc:
            # Keep the appeal and its case consistent: if the case cannot be
            # resolved (e.g. missing evidence for a code that demands it), the
            # appeal decision must not stand either.
            db.execute(
                "UPDATE appeals SET status = 'reviewing', outcome_note = NULL, "
                "reviewed_by = NULL, resolved_at = NULL WHERE id = ?", (appeal_id,))
            raise AppealError(str(exc)) from exc

    compliance.record_staff_action(
        actor_pseudonym=privacy.hash_id(f"staff:{analyst_id}"),
        action=f"appeal_{status}", target=f"appeal:{appeal_id}",
        meta={"reason_code": reason_code, "counts_as_false_positive": counts_fp})
    db.log_activity(appeal["user_id"], "appeal_reviewed",
                    {"appeal_id": appeal_id, "status": status})
    return get(appeal_id)


def start_review(appeal_id: int, analyst_id: int) -> dict:
    appeal = get(appeal_id)
    if not appeal:
        raise AppealError("Appeal not found.")
    if appeal["status"] != "submitted":
        raise AppealError("Only a submitted appeal can be picked up.")
    db.execute("UPDATE appeals SET status = 'reviewing', reviewed_by = ? WHERE id = ?",
               (analyst_id, appeal_id))
    if appeal["case_id"]:
        cases.set_status(appeal["case_id"], "investigating", analyst_id,
                         note="Analyst picked up the appeal.")
    return get(appeal_id)


def purge_expired() -> int:
    """Delete appeals past the retention window. Returns the number removed."""
    days = _retention_days()
    with db.db() as con:
        cur = con.execute(
            "DELETE FROM appeals WHERE resolved_at IS NOT NULL "
            "AND resolved_at < datetime('now', ?)", (f"-{days} days",))
        return cur.rowcount or 0

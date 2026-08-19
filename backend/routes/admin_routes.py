"""
Fraud-team (admin) API. Role-gated: every route requires an 'admin' session.

Gives the fraud team the queue view the brief asks for: open alerts and
escalations, per-user posture, the notification outbox, chatbot escalations,
and the tamper-evident audit chain check. Admin actions (freeze, status
changes) are themselves written to the activity log — accountability applies
to staff too.
"""
import json

from flask import Blueprint, g, jsonify, request

from engine import (appeals, auth, cases, compliance, db, feedback, monitoring,
                    notifier)
from engine.validation import Validator
from routes.common import require_auth

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

_ALERT_STATUSES = {"new", "acknowledged", "escalated", "resolved"}


@admin_bp.route("/overview")
@require_auth(role="admin")
def overview():
    def count(sql, params=()):
        return (db.query_one(sql, params) or {}).get("n", 0)
    return jsonify({
        "users": count("SELECT COUNT(*) AS n FROM users"),
        "frozen_accounts": count("SELECT COUNT(*) AS n FROM users WHERE frozen = 1"),
        "alerts_open": count("SELECT COUNT(*) AS n FROM alerts WHERE status IN ('new','escalated')"),
        "alerts_critical": count(
            "SELECT COUNT(*) AS n FROM alerts WHERE severity = 'critical' "
            "AND status IN ('new','escalated')"),
        "escalations": count("SELECT COUNT(*) AS n FROM alerts WHERE status = 'escalated'"),
        "flagged_transactions": count("SELECT COUNT(*) AS n FROM transactions WHERE flagged = 1"),
        "sim_events_30d": count(
            "SELECT COUNT(*) AS n FROM sim_events WHERE occurred_at >= datetime('now','-30 days')"),
        "chat_messages": count("SELECT COUNT(*) AS n FROM chat_logs"),
        "outbox": count("SELECT COUNT(*) AS n FROM outbox"),
        "audit": compliance.verify_audit_chain(),
    })


@admin_bp.route("/alerts")
@require_auth(role="admin")
def alerts():
    status = request.args.get("status")
    sql = ("SELECT a.*, u.email, u.display_name FROM alerts a "
           "LEFT JOIN users u ON u.id = a.user_id ")
    params: tuple = ()
    if status in _ALERT_STATUSES:
        sql += "WHERE a.status = ? "
        params = (status,)
    sql += "ORDER BY a.created_at DESC LIMIT 100"
    rows = db.query_all(sql, params)
    for r in rows:
        r["meta"] = json.loads(r["meta"] or "{}")
    return jsonify(rows)


@admin_bp.route("/alerts/<int:alert_id>/status", methods=["POST"])
@require_auth(role="admin")
def set_alert_status(alert_id: int):
    status = (request.get_json(silent=True) or {}).get("status", "")
    if status not in _ALERT_STATUSES:
        return jsonify({"error": f"status must be one of {sorted(_ALERT_STATUSES)}"}), 400
    row = db.query_one("SELECT * FROM alerts WHERE id = ?", (alert_id,))
    if not row:
        return jsonify({"error": "Alert not found."}), 404
    db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    db.log_activity(g.user["id"], "admin_alert_status",
                    {"alert_id": alert_id, "status": status})
    if status == "resolved" and row["user_id"]:
        target = auth.get_user(row["user_id"])
        if target:
            notifier.send(target, "Your case was resolved",
                          "The fraud team reviewed and resolved the alert on your "
                          "account. Contact us if anything still looks wrong.",
                          alert_type=None)
    return jsonify({"ok": True})


@admin_bp.route("/users")
@require_auth(role="admin")
def users():
    rows = db.query_all(
        "SELECT id, email, display_name, role, operator, frozen, points, "
        "created_at, last_login FROM users ORDER BY id")
    for u in rows:
        open_alerts = db.query_one(
            "SELECT COUNT(*) AS n FROM alerts WHERE user_id = ? AND status IN ('new','escalated')",
            (u["id"],))
        u["open_alerts"] = (open_alerts or {}).get("n", 0)
    return jsonify(rows)


@admin_bp.route("/users/<int:user_id>/freeze", methods=["POST"])
@require_auth(role="admin")
def freeze_user(user_id: int):
    frozen = bool((request.get_json(silent=True) or {}).get("frozen", True))
    target = auth.get_user(user_id)
    if not target:
        return jsonify({"error": "User not found."}), 404
    auth.set_frozen(user_id, frozen, by=f"admin:{g.user['id']}")
    notifier.send(target,
                  "Account frozen by the fraud team" if frozen else "Account unfrozen",
                  ("The fraud team froze your account as a protective measure. "
                   "Call the bank to verify your identity and restore access."
                   if frozen else
                   "The fraud team has restored normal operation on your account."),
                  alert_type=None)
    return jsonify({"ok": True, "frozen": frozen})


@admin_bp.route("/stats")
@require_auth(role="admin")
def stats():
    """Time-series + distribution data for the fraud-desk charts."""
    per_day = db.query_all(
        "SELECT date(created_at) AS day, COUNT(*) AS n, "
        "SUM(CASE WHEN severity='critical' THEN 1 ELSE 0 END) AS critical "
        "FROM alerts WHERE created_at >= datetime('now','-7 days') "
        "GROUP BY date(created_at) ORDER BY day")
    by_type = db.query_all(
        "SELECT alert_type, COUNT(*) AS n FROM alerts GROUP BY alert_type ORDER BY n DESC")
    decisions = db.query_all(
        "SELECT json_extract(meta,'$.decision') AS decision, COUNT(*) AS n "
        "FROM activity_log WHERE action='pre_otp_check' GROUP BY decision")
    txn = db.query_one(
        "SELECT COUNT(*) AS total, SUM(flagged) AS flagged, "
        "SUM(CASE WHEN status='held' THEN 1 ELSE 0 END) AS held FROM transactions")
    return jsonify({"alerts_per_day": per_day, "alerts_by_type": by_type,
                    "pre_otp_decisions": decisions, "transactions": txn})


@admin_bp.route("/users/<int:user_id>/timeline")
@require_auth(role="admin")
def user_timeline(user_id: int):
    """One merged, time-ordered case view of a subscriber for investigations."""
    target = auth.get_user(user_id)
    if not target:
        return jsonify({"error": "User not found."}), 404
    events = []
    for a in db.query_all(
            "SELECT created_at, alert_type, severity, message, status FROM alerts "
            "WHERE user_id = ? ORDER BY created_at DESC LIMIT 25", (user_id,)):
        events.append({"when": a["created_at"], "kind": "alert",
                       "label": f"[{a['severity']}] {a['alert_type']}: {a['message'][:140]}",
                       "status": a["status"]})
    for s in db.query_all(
            "SELECT occurred_at, event_type, details, risk_score FROM sim_events "
            "WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 15", (user_id,)):
        events.append({"when": s["occurred_at"], "kind": "sim_event",
                       "label": f"{s['event_type']} (risk {s['risk_score']}): {s['details'] or ''}"})
    for t in db.query_all(
            "SELECT occurred_at, amount, merchant, flagged, status FROM transactions "
            "WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 20", (user_id,)):
        events.append({"when": t["occurred_at"], "kind": "transaction",
                       "label": f"NPR {t['amount']:,.0f} at {t['merchant'] or '—'} "
                                f"({t['status']}{', flagged' if t['flagged'] else ''})"})
    for l in db.query_all(
            "SELECT created_at, action FROM activity_log WHERE user_id = ? "
            "AND action IN ('login_ok','login_fail','otp_fail','freeze','unfreeze',"
            "'pre_otp_check','password_reset','session_revoked') "
            "ORDER BY created_at DESC LIMIT 25", (user_id,)):
        events.append({"when": l["created_at"], "kind": "activity", "label": l["action"]})
    events.sort(key=lambda e: e["when"], reverse=True)
    return jsonify({"user": {"id": target["id"], "email": target["email"],
                             "display_name": target["display_name"],
                             "operator": target["operator"],
                             "frozen": bool(target["frozen"])},
                    "events": events[:60]})


@admin_bp.route("/outbox")
@require_auth(role="admin")
def outbox():
    return jsonify(db.query_all(
        "SELECT o.*, u.email FROM outbox o LEFT JOIN users u ON u.id = o.user_id "
        "ORDER BY o.id DESC LIMIT 100"))


# --- Case management with reason codes (improvement #2) -----------------------
@admin_bp.route("/reason-codes")
@require_auth(role="admin")
def reason_codes():
    """The taxonomy an analyst must pick from when resolving a case."""
    return jsonify(cases.taxonomy())


@admin_bp.route("/cases")
@require_auth(role="admin")
def list_cases():
    v = Validator(dict(request.args))
    v.string("status", choices=set(cases.STATUSES))
    v.number("limit", integer=True, minimum=1, maximum=500, default=100)
    clean = v.done()
    rows = cases.list_cases(
        status=clean["status"] or None,
        overdue_only=request.args.get("overdue") == "1",
        limit=clean["limit"])
    return jsonify({"cases": rows, "stats": cases.queue_stats()})


@admin_bp.route("/cases/<int:case_id>")
@require_auth(role="admin")
def get_case(case_id: int):
    case = cases.get_case(case_id)
    if not case:
        return jsonify({"error": "Case not found."}), 404
    return jsonify({"case": case, "notes": cases.notes(case_id)})


@admin_bp.route("/cases", methods=["POST"])
@require_auth(role="admin")
def create_case():
    v = Validator(request.get_json(silent=True))
    v.string("title", required=True, max_len=200)
    v.string("severity", default="medium", choices=set(cases.SEVERITIES))
    v.number("user_id", integer=True, minimum=1)
    v.string("note", max_len=4000)
    clean = v.done()
    case = cases.open_case(
        clean["user_id"], clean["title"], severity=clean["severity"],
        source="manual", opened_by=f"admin:{g.user['id']}", note=clean["note"])
    return jsonify(case), 201


@admin_bp.route("/cases/<int:case_id>/notes", methods=["POST"])
@require_auth(role="admin")
def add_case_note(case_id: int):
    if not cases.get_case(case_id):
        return jsonify({"error": "Case not found."}), 404
    v = Validator(request.get_json(silent=True))
    v.string("body", required=True, max_len=4000)
    cases.add_note(case_id, g.user["id"], v.done()["body"])
    return jsonify({"ok": True, "notes": cases.notes(case_id)})


@admin_bp.route("/cases/<int:case_id>/status", methods=["POST"])
@require_auth(role="admin")
def case_status(case_id: int):
    v = Validator(request.get_json(silent=True))
    v.string("status", required=True, choices={"open", "investigating",
                                               "awaiting_customer"})
    v.string("note", max_len=2000)
    clean = v.done()
    try:
        case = cases.set_status(case_id, clean["status"], g.user["id"],
                                note=clean["note"])
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    if not case:
        return jsonify({"error": "Case not found."}), 404
    return jsonify(case)


@admin_bp.route("/cases/<int:case_id>/assign", methods=["POST"])
@require_auth(role="admin")
def case_assign(case_id: int):
    v = Validator(request.get_json(silent=True))
    v.number("analyst_id", integer=True, minimum=1)
    case = cases.assign(case_id, v.done()["analyst_id"], g.user["id"])
    if not case:
        return jsonify({"error": "Case not found."}), 404
    return jsonify(case)


@admin_bp.route("/cases/<int:case_id>/resolve", methods=["POST"])
@require_auth(role="admin")
def case_resolve(case_id: int):
    """
    Close a case with a coded outcome. The outcome is derived from the reason
    code inside the engine — it is deliberately NOT accepted from the client,
    so a resolution cannot claim one thing while citing another.
    """
    v = Validator(request.get_json(silent=True))
    v.string("reason_code", required=True, max_len=16)
    v.string("note", max_len=2000)
    v.string("evidence", max_len=2000)
    clean = v.done()
    try:
        case = cases.resolve(case_id, clean["reason_code"], g.user["id"],
                             note=clean["note"], evidence=clean["evidence"])
    except cases.ResolutionError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(case)


@admin_bp.route("/cases/<int:case_id>/reopen", methods=["POST"])
@require_auth(role="admin")
def case_reopen(case_id: int):
    v = Validator(request.get_json(silent=True))
    v.string("note", required=True, max_len=2000)
    case = cases.reopen(case_id, g.user["id"], v.done()["note"])
    if not case:
        return jsonify({"error": "Case not found."}), 404
    return jsonify(case)


# --- Appeals queue (improvement #3) -------------------------------------------
@admin_bp.route("/appeals")
@require_auth(role="admin")
def appeal_queue():
    status = request.args.get("status")
    return jsonify({"appeals": appeals.list_queue(
        status if status in appeals.STATUSES else None),
        "stats": feedback.appeal_stats()})


@admin_bp.route("/appeals/<int:appeal_id>/claim", methods=["POST"])
@require_auth(role="admin")
def appeal_claim(appeal_id: int):
    try:
        return jsonify(appeals.start_review(appeal_id, g.user["id"]))
    except appeals.AppealError as exc:
        return jsonify({"error": str(exc)}), 400


@admin_bp.route("/appeals/<int:appeal_id>/review", methods=["POST"])
@require_auth(role="admin")
def appeal_review(appeal_id: int):
    body = request.get_json(silent=True) or {}
    if not isinstance(body.get("uphold"), bool):
        # Deliberately strict: whether the subscriber was right is the whole
        # decision, so it must be stated explicitly rather than defaulted.
        return jsonify({"error": "uphold must be supplied as true or false."}), 400
    v = Validator(body)
    v.boolean("uphold")
    v.string("reason_code", required=True, max_len=16)
    v.string("note", max_len=2000)
    v.string("evidence", max_len=2000)
    clean = v.done()
    try:
        result = appeals.review(appeal_id, g.user["id"], bool(clean["uphold"]),
                                clean["reason_code"], note=clean["note"],
                                evidence=clean["evidence"])
    except appeals.AppealError as exc:
        return jsonify({"error": str(exc)}), 400
    target = auth.get_user(result["user_id"])
    if target:
        notifier.send(
            target,
            "Your appeal was upheld" if result["status"] == "upheld"
            else "Your appeal was reviewed",
            ("We reviewed your appeal and agree the decision was wrong. Thank "
             "you — this helps us reduce how often genuine sign-ins are stopped."
             if result["status"] == "upheld" else
             "We reviewed your appeal. On the evidence available we are keeping "
             "the original decision. You can reply if you have more information."),
            alert_type=None)
    return jsonify(result)


# --- Drift & fairness monitoring (improvement #4) -----------------------------
@admin_bp.route("/monitoring")
@require_auth(role="admin")
def monitoring_report():
    v = Validator(dict(request.args))
    v.number("days", integer=True, minimum=1, maximum=365, default=30)
    return jsonify(monitoring.report(days=v.done()["days"]))


@admin_bp.route("/feedback")
@require_auth(role="admin")
def feedback_report():
    """The false-positive rate measured from human-coded outcomes."""
    return jsonify(feedback.report())


@admin_bp.route("/chatlogs")
@require_auth(role="admin")
def chatlogs():
    return jsonify(db.query_all(
        "SELECT c.id, c.user_id, u.email, c.lang, c.query, c.intent, c.escalated, "
        "c.created_at FROM chat_logs c LEFT JOIN users u ON u.id = c.user_id "
        "ORDER BY c.id DESC LIMIT 100"))

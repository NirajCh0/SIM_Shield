"""
Account-level security risk score for the user dashboard.

The detection engine scores one LOGIN ATTEMPT; this module scores the ACCOUNT's
current posture by aggregating what the database has seen recently:

    * open critical / warning alerts
    * SIM events in the last 30 days (swaps, IMSI/ICCID changes)
    * flagged-transaction ratio in the last 30 days
    * brand-new devices in the last 7 days
    * sequence anomaly of the latest login vs the user's own login history

Output is 0-100 with a level (LOW / GUARDED / ELEVATED / HIGH) and plain-language
reasons — the same explainability contract as the login detector.
"""
import json
from datetime import datetime, timedelta

from . import anomaly, db


def _iso_days_ago(days: int) -> str:
    return (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")


def _level(score: float) -> str:
    if score < 20:
        return "LOW"
    if score < 45:
        return "GUARDED"
    if score < 70:
        return "ELEVATED"
    return "HIGH"


def compute(user: dict) -> dict:
    uid = user["id"]
    score, reasons = 0.0, []

    if user["frozen"]:
        return {"score": 100.0, "level": "FROZEN",
                "reasons": ["Account is frozen at your request — unfreeze it "
                            "from Settings once the danger has passed."],
                "sequence": None}

    # open alerts
    open_alerts = db.query_all(
        "SELECT severity FROM alerts WHERE user_id = ? AND status IN ('new','escalated')",
        (uid,))
    crit = sum(1 for a in open_alerts if a["severity"] == "critical")
    warn = sum(1 for a in open_alerts if a["severity"] == "warning")
    if crit:
        score += min(40, crit * 25)
        reasons.append(f"{crit} unresolved critical alert(s) on your account.")
    if warn:
        score += min(15, warn * 5)
        reasons.append(f"{warn} unresolved warning(s) — review them below.")

    # SIM events (30 days)
    sim_events = db.query_all(
        "SELECT event_type FROM sim_events WHERE user_id = ? AND occurred_at >= ?",
        (uid, _iso_days_ago(30)))
    swaps = sum(1 for e in sim_events
                if e["event_type"] in ("sim_swap", "imsi_change", "iccid_change"))
    if swaps:
        score += min(35, swaps * 20)
        reasons.append(f"{swaps} SIM change event(s) in the last 30 days — "
                       "the primary SIM-swap indicator.")

    # flagged transactions (30 days)
    txns = db.query_one(
        "SELECT COUNT(*) AS n, COALESCE(SUM(flagged),0) AS f FROM transactions "
        "WHERE user_id = ? AND occurred_at >= ?", (uid, _iso_days_ago(30)))
    if txns and txns["n"]:
        ratio = txns["f"] / txns["n"]
        if ratio > 0:
            score += min(20, ratio * 40)
            reasons.append(f"{txns['f']} of your last {txns['n']} transactions were flagged.")

    # held transactions awaiting OTP release
    held = db.query_one(
        "SELECT COUNT(*) AS n FROM transactions WHERE user_id = ? AND status = 'held'",
        (uid,))
    if (held or {}).get("n", 0):
        score += 10
        reasons.append(f"{held['n']} transaction(s) are on a post-SIM-change hold "
                       "awaiting your release code.")

    # new devices (7 days)
    new_dev = db.query_one(
        "SELECT COUNT(*) AS n FROM devices WHERE user_id = ? AND first_seen >= ?",
        (uid, _iso_days_ago(7)))
    if (new_dev or {}).get("n", 0) > 1:
        score += 10
        reasons.append(f"{new_dev['n']} new device(s) signed in within the last week.")

    # sequential login-behaviour anomaly (Markov model over the user's history)
    logins = db.query_all(
        "SELECT action, meta, created_at FROM activity_log WHERE user_id = ? "
        "AND action IN ('login_ok','otp_ok') ORDER BY created_at ASC LIMIT 200", (uid,))
    seq = None
    if len(logins) >= 2:
        tokens = []
        for row in logins:
            meta = json.loads(row["meta"] or "{}")
            tokens.append(anomaly.event_token(row["created_at"],
                                              meta.get("device_known", True)))
        seq = anomaly.sequence_anomaly(tokens[:-1], tokens[-1])
        if seq["score"] is not None and seq["score"] >= 50:
            score += min(15, seq["score"] * 0.15)
            reasons.append("Your latest sign-in did not match your usual login pattern.")

    score = round(min(score, 100.0), 1)
    if not reasons:
        reasons.append("No unusual activity — your account posture looks healthy.")
    return {"score": score, "level": _level(score), "reasons": reasons, "sequence": seq}


def snapshot(user_id: int, risk: dict) -> None:
    """
    Append the score to risk_history so the dashboard can chart the trend.
    De-duplicated: skipped when the last snapshot is recent AND unchanged.
    """
    last = db.query_one(
        "SELECT score, created_at FROM risk_history WHERE user_id = ? "
        "ORDER BY id DESC LIMIT 1", (user_id,))
    if last and last["score"] == risk["score"]:
        try:
            age = datetime.now() - datetime.fromisoformat(last["created_at"])
            if age < timedelta(minutes=30):
                return
        except ValueError:
            pass
    db.execute("INSERT INTO risk_history (user_id, score, level, created_at) "
               "VALUES (?,?,?,?)", (user_id, risk["score"], risk["level"], db.now()))


def history(user_id: int, limit: int = 40) -> list[dict]:
    return db.query_all(
        "SELECT score, level, created_at FROM risk_history WHERE user_id = ? "
        "ORDER BY id DESC LIMIT ?", (user_id, limit))[::-1]

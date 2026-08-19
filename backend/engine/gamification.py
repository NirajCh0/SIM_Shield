"""
Security-awareness gamification: points for engaging with the awareness
features, badges at config-driven thresholds (config.yaml -> gamification).

The point of the mechanic is behavioural: users who complete the study, quiz
the chatbot and work through the security checklist measurably raise their
awareness (evaluated in the mixed-methods study), so the system rewards
exactly those actions. Awards are idempotent per one-shot events.
"""
import json

from . import db
from .config_loader import load_config

# one-shot events may only ever be awarded once per user
_ONE_SHOT = {"study_completed", "quiz_perfect"}


def award(user_id: int, event: str) -> dict:
    """Grant points for `event`; returns {points, new_badges, awarded}."""
    cfg = load_config()["gamification"]
    pts = cfg["points"].get(event)
    if pts is None:
        return {"awarded": False, "points": 0, "new_badges": []}

    if event in _ONE_SHOT:
        seen = db.query_one(
            "SELECT COUNT(*) AS n FROM activity_log WHERE user_id = ? AND action = ?",
            (user_id, f"gamify_{event}"))
        if (seen or {}).get("n", 0) > 0:
            return {"awarded": False, "points": 0, "new_badges": []}

    user = db.query_one("SELECT points, badges FROM users WHERE id = ?", (user_id,))
    if not user:
        return {"awarded": False, "points": 0, "new_badges": []}

    total = (user["points"] or 0) + pts
    have = set(json.loads(user["badges"] or "[]"))
    new_badges = [b for b in cfg["badges"]
                  if b["id"] not in have and total >= b["min_points"]]
    badges = sorted(have | {b["id"] for b in new_badges})

    db.execute("UPDATE users SET points = ?, badges = ? WHERE id = ?",
               (total, json.dumps(badges), user_id))
    db.log_activity(user_id, f"gamify_{event}", {"points": pts})
    return {"awarded": True, "points": pts, "total": total, "new_badges": new_badges}


def badge_catalog() -> list[dict]:
    return load_config()["gamification"]["badges"]

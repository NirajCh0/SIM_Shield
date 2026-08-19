"""
Synthetic demo-profile loading, with time-relative date resolution.

WHY THIS EXISTS
Profiles originally pinned absolute dates chosen against a fixed "demo today"
(2026-07-05). But the risk engine measures SIM age against the REAL current
date, so those fixtures decayed silently: a SIM authored as "activated 1 day
ago" read as 39 days old five weeks later, dropping its SIM-integrity tier from
100 to 20 and turning a BLOCK scenario into VERIFY. The demo looked fine and the
regression suite quietly went wrong.

So a profile may now express ages RELATIVELY, and they are resolved to concrete
dates at load time:

    sim_activation_days_ago: 1      -> sim_activation_date = today - 1 day
    account_created_days_ago: 1800  -> account_created     = today - 1800 days
    last_login_hours_ago: 3         -> last_login.timestamp = now - 3 hours

Absolute values are still honoured when no relative field is present, so
profiles that genuinely want a fixed historical date can keep one.
"""
import json
import os
from datetime import datetime, timedelta

USERS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                         "data", "users")


def resolve_dates(profile: dict, now: datetime | None = None) -> dict:
    """Return a copy of `profile` with any relative age fields resolved."""
    now = now or datetime.now()
    p = dict(profile)

    days = p.pop("sim_activation_days_ago", None)
    if days is not None:
        p["sim_activation_date"] = (now - timedelta(days=float(days))).date().isoformat()

    days = p.pop("account_created_days_ago", None)
    if days is not None:
        p["account_created"] = (now - timedelta(days=float(days))).date().isoformat()

    hours = p.pop("last_login_hours_ago", None)
    if hours is not None:
        last = dict(p.get("last_login") or {})
        last["timestamp"] = (now - timedelta(hours=float(hours))).isoformat(timespec="seconds")
        p["last_login"] = last

    return p


def load(user_id: str) -> dict | None:
    """Load a synthetic profile by id, with dates resolved. None if unknown."""
    if not user_id or not user_id.isidentifier():   # reject path traversal
        return None
    path = os.path.join(USERS_DIR, f"{user_id}.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return resolve_dates(json.load(f))


def list_all() -> list[dict]:
    """Summary rows for every synthetic profile (dates resolved)."""
    out = []
    for fname in sorted(os.listdir(USERS_DIR)):
        if not fname.endswith(".json"):
            continue
        with open(os.path.join(USERS_DIR, fname), "r", encoding="utf-8") as f:
            p = resolve_dates(json.load(f))
        out.append({"user_id": p["user_id"],
                    "display_name": p.get("display_name", p["user_id"]),
                    "operator": p.get("operator"),
                    "sim_activation_date": p.get("sim_activation_date")})
    return out

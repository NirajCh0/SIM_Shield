"""
Component 2: rule-based behavioral signals (explainable red flags).

These sit IN FRONT of the ML model: each triggered rule adds risk points and a
plain-language reason, so a human can always see WHY a login looked risky
(supports the 'right to explanation' in compliance.yaml). The same function also
returns a behavioral feature dict consumed downstream by telecom_features.build.

Signal set is derived from the IJARCCE-2025 paper's feature ideas (IMEI-change
frequency, geographic anomalies, login patterns) and extended with the telecom
identity signals present in the training dataset (IMSI/ICCID change, SIM-swap
count, IP change).
"""
from datetime import datetime

from .risk_engine import haversine_km


def _parse_ts(ts) -> datetime | None:
    """
    Parse an ISO timestamp, tolerating a trailing 'Z'. Returns None for a
    missing or unparseable value rather than raising: the timestamp is an
    OPTIONAL attempt field, and a caller omitting it previously produced an
    AttributeError deep in the scoring path and a 500 from the API
    (surfaced by the validation work — see SECURITY_REMEDIATION.md F16).
    Signals that need a timestamp simply do not fire without one.
    """
    if not ts or not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def evaluate(attempt: dict, profile: dict, cfg: dict) -> dict:
    """
    Returns:
        { score: float (0-cap), flags: [{id,label,points}...],
          features: { imei_changed, new_device, impossible_travel, ... } }
    """
    b = cfg["behavioral"]
    rules = b["rules"]
    flags = []

    current = attempt.get("current_location")
    imei = attempt.get("imei")
    known_imeis = profile.get("known_imeis", [])
    last_login = profile.get("last_login")

    # --- Device: IMEI change / new device -----------------------------------
    # A device already on the user's registered list is NOT a "change" — people
    # legitimately alternate between a phone and a tablet. Previously this
    # compared only against the most recently used IMEI, so a subscriber with
    # two registered handsets scored a 60-point device-change flag simply for
    # picking up their other phone (a false positive that pushed an ordinary
    # office login out of ALLOW). It now requires the device to be BOTH
    # different from last time AND unregistered.
    new_device = bool(imei and imei not in known_imeis)
    imei_changed = bool(imei and known_imeis and imei != known_imeis[-1] and new_device)
    if imei_changed:
        flags.append({"id": "imei_change", **rules["imei_change"]})
    if new_device:
        flags.append({"id": "new_device", **rules["new_device"]})

    # --- Telecom identity signals (from the operator feed / attempt) ---------
    if int(attempt.get("imsi_change_flag", 0)):
        flags.append({"id": "imsi_change", **rules["imsi_change"]})
    if int(attempt.get("iccid_change_flag", 0)):
        flags.append({"id": "iccid_change", **rules["iccid_change"]})
    num_swaps_30d = int(profile.get("num_sim_changes_last_30d", 0))
    if num_swaps_30d >= b["multi_swap_threshold"]:
        flags.append({"id": "multiple_sim_swaps", **rules["multiple_sim_swaps"]})
    if int(attempt.get("ip_change_flag", 0)):
        flags.append({"id": "ip_change", **rules["ip_change"]})

    # --- Impossible travel ---------------------------------------------------
    impossible_travel = False
    if current and last_login:
        dist = haversine_km(current["lat"], current["lon"],
                            last_login["lat"], last_login["lon"])
        now_ts = _parse_ts(attempt.get("timestamp"))
        then_ts = _parse_ts(last_login.get("timestamp"))
        hours = None
        if now_ts and then_ts:
            try:
                hours = (now_ts - then_ts).total_seconds() / 3600.0
            except TypeError:
                # one side timezone-aware, the other naive — not comparable
                hours = None
        if hours and hours > 0 and dist / hours > b["impossible_travel_kmh"]:
            impossible_travel = True
            flags.append({"id": "impossible_travel", **rules["impossible_travel"]})

    # --- Odd-hour login ------------------------------------------------------
    parsed = _parse_ts(attempt.get("timestamp"))
    hour = parsed.hour if parsed else None
    if hour is not None and b["odd_hour_start"] <= hour <= b["odd_hour_end"]:
        flags.append({"id": "odd_hour", **rules["odd_hour"]})

    # --- Rapid logins / failed-login burst ----------------------------------
    logins_24h = int(attempt.get("logins_last_24h", 0))
    failed_24h = int(attempt.get("failed_logins_last_24h", 0))
    if logins_24h >= b["rapid_login_threshold"]:
        flags.append({"id": "rapid_logins", **rules["rapid_logins"]})
    if failed_24h >= b["failed_login_threshold"]:
        flags.append({"id": "failed_login_burst", **rules["failed_login_burst"]})

    # --- SIM-location mismatch (operator-fed) --------------------------------
    # A phone and its SIM travel together, so a genuine traveller shows no
    # mismatch. A login claiming one place while the operator reports the SIM
    # on a tower somewhere else means the person signing in is not holding the
    # phone that owns the number — spoofed GPS, a VPN, or a stolen session.
    # Requires a USABLE operator reading. Unavailable, slow, stale, rate-limited,
    # malformed, disagreeing or unconsented data all leave this signal silent
    # rather than assumed safe — `location_mismatch` returns mismatch=False on
    # every degraded path, so an operator outage cannot raise anyone's score
    # (see engine/operator.py and tests/test_operator_adapter.py).
    from . import operator as _operator
    sim_loc = _operator.location_mismatch(
        profile, attempt, threshold_km=b.get("sim_location_mismatch_km", 100))
    if sim_loc["mismatch"]:
        rule = dict(rules["sim_location_mismatch"])
        rule["label"] = (f"{rule['label']} — SIM is on a tower near "
                         f"{sim_loc['sim_area']}, but this login claims "
                         f"{sim_loc['claimed_area']} (~{sim_loc['km']:.0f} km apart)")
        flags.append({"id": "sim_location_mismatch", **rule})

    score = min(b["cap"], sum(f["points"] for f in flags))

    features = {
        "imei_changed": int(imei_changed),
        "new_device": int(new_device),
        "impossible_travel": int(impossible_travel),
        "hour_of_day": hour if hour is not None else 12,
        "logins_last_24h": logins_24h,
        "failed_logins_last_24h": failed_24h,
        "sim_location_mismatch": int(sim_loc["available"] and sim_loc["mismatch"]),
    }
    # Surface WHY operator data did or did not count, so a degraded check is
    # visible to the user and the admin rather than silently absent.
    return {"score": float(score), "flags": flags, "features": features,
            "operator": sim_loc.get("explain")}

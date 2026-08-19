"""
Component 1: the classic rule-based risk score.

Fuses SIM integrity (how recently the SIM was activated) with location
intelligence (distance from the user's safe zones, passed through a sigmoid
curve). This mirrors the Sim-Swap-Sentinel reference but is fully
config-driven and broken into testable functions.
"""
import math
from datetime import datetime


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    """Great-circle distance between two points in kilometres."""
    R = 6371.0
    d_lat = math.radians(lat2 - lat1)
    d_lon = math.radians(lon2 - lon1)
    lat1_r, lat2_r = math.radians(lat1), math.radians(lat2)
    a = math.sin(d_lat / 2) ** 2 + math.cos(lat1_r) * math.cos(lat2_r) * math.sin(d_lon / 2) ** 2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def days_since(date_str: str) -> int:
    """Days between an ISO date (YYYY-MM-DD) and now."""
    activation = datetime.strptime(date_str, "%Y-%m-%d")
    return (datetime.now() - activation).days


def sim_integrity_score(activation_date: str, cfg: dict) -> tuple[float, int]:
    """
    Map SIM age to a 0-100 risk score using the configured tiers.
    Returns (score, days_since_activation).
    """
    age_days = days_since(activation_date)
    for tier in cfg["rule_engine"]["sim_integrity_tiers"]:
        max_days = tier["max_days"]
        if max_days is None or age_days <= max_days:
            return float(tier["score"]), age_days
    return 5.0, age_days  # fallback (should be covered by null tier)


def location_score(current, safe_zones, cfg: dict) -> tuple[float, float]:
    """
    Risk based on distance from the nearest safe zone, via a sigmoid curve.
    Returns (score, nearest_distance_km). If no location/zones are available,
    treats it as maximum location risk (can't confirm a known place).
    """
    loc_cfg = cfg["rule_engine"]["location"]
    if not current or not safe_zones:
        return 100.0, float("inf")

    nearest = min(
        haversine_km(current["lat"], current["lon"], z["lat"], z["lon"])
        for z in safe_zones
    )

    if nearest <= loc_cfg["safe_radius_km"]:
        return 0.0, nearest

    s = loc_cfg["sigmoid"]
    score = s["L"] / (1 + math.exp(-s["k"] * (nearest - s["x0"])))
    return float(score), nearest


def rule_score(activation_date: str, current_location, safe_zones, cfg: dict) -> dict:
    """
    Combine SIM integrity + location into a single 0-100 rule score.
    Returns a breakdown dict for transparency in the UI.
    """
    weights = cfg["rule_engine"]["weights"]
    sim_s, age_days = sim_integrity_score(activation_date, cfg)
    loc_s, distance = location_score(current_location, safe_zones, cfg)

    combined = weights["sim_integrity"] * sim_s + weights["location"] * loc_s

    return {
        "score": round(combined, 1),
        "sim_integrity_score": round(sim_s, 1),
        "location_score": round(loc_s, 1),
        "days_since_sim_activation": age_days,
        "nearest_safe_zone_km": (None if distance == float("inf") else round(distance, 2)),
    }

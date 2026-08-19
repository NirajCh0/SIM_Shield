"""
Telecom feature extraction (the bridge to the real 100k-row dataset).

The public SIM-swap dataset (sim_swap_fraud_dataset_100000.csv) is labelled with
11 TELECOM-side features. SIMShield's Random Forest is trained on exactly those
features, so at scoring time we must derive the same 11 numbers from what we
actually observe: the stored user profile + the incoming login attempt.

This module is the single source of truth for that mapping. Several features map
directly (recent_sim_activation_days == days since SIM activation); others are
derived (a geolocation-similarity score from the distance to the safe zone); and
a few are optional telecom signals that come from the profile/attempt and default
to the SAFE value when a bank hasn't wired up the operator (HLR/HSS) feed yet.

Keep the returned dict's keys and the ORDER in config.yaml -> ml.features in sync.
"""
import math

from .risk_engine import days_since, haversine_km


def _geo_similarity(distance_km) -> float:
    """
    Map distance-from-safe-zone to a 0..1 'geolocation similarity' score, the
    analogue of the dataset's otp_and_sim_change_geo_hash_length (higher = the
    OTP location and the SIM-change location look like the same place).

    At the safe zone -> ~1.0; it decays smoothly, ~0.5 at 25 km, ~0 far away.
    """
    if distance_km is None or math.isinf(distance_km):
        return 0.0
    return round(1.0 / (1.0 + (distance_km / 25.0)), 4)


def build(attempt: dict, profile: dict, rule: dict, behav: dict) -> dict:
    """
    Assemble the 11 telecom features the model was trained on.

    attempt : the incoming login (may carry optional telecom signals)
    profile : the stored user profile
    rule    : output of risk_engine.rule_score (has days_since / distance)
    behav   : output of signals.evaluate (has imei_changed, etc.)

    Missing optional telecom signals default to the SAFE (non-fraud) value so the
    model degrades gracefully to the rule/behavioral evidence it does have.
    """
    f = behav["features"]

    # sim_swap_time_gap_minutes: minutes between the OTP request and the SIM
    # change. A small gap is highly suspicious. Unknown -> large (safe) default.
    time_gap = attempt.get("otp_sim_gap_minutes")
    if time_gap is None:
        time_gap = 10000

    # account age (days) from an optional account_created date on the profile.
    account_created = profile.get("account_created")
    account_age_days = days_since(account_created) if account_created else 1825  # ~5y default

    return {
        "sim_swap_time_gap_minutes": float(time_gap),
        "device_change_flag": int(f["imei_changed"]),
        "sim_type_change_flag": int(attempt.get("sim_type_change_flag", 0)),
        "imsi_change_flag": int(attempt.get("imsi_change_flag", 0)),
        "iccid_change_flag": int(attempt.get("iccid_change_flag", 0)),
        "otp_and_sim_change_geo_hash_length": _geo_similarity(rule.get("nearest_safe_zone_km")),
        "recent_sim_activation_days": float(rule["days_since_sim_activation"]),
        "num_sim_changes_last_30d": int(profile.get("num_sim_changes_last_30d", 0)),
        "previous_sim_holder_tenure_days": float(profile.get("previous_sim_holder_tenure_days", 900)),
        "account_age_days": float(account_age_days),
        "ip_change_flag": int(attempt.get("ip_change_flag", 0)),
    }

"""
Orchestrator: fuses the three components into a final risk score + decision.

    rule_score   (SIM integrity + location)              -> 0..100
    behavioral   (explainable red-flag rules)            -> 0..100  + flags
    ml_score     (Random Forest P(fraud) on 100k data)   -> 0..100  (optional)

The ML component now runs on the 11 TELECOM features derived by
telecom_features.build() - the same features the model was trained on. The final
score is a weighted average over the AVAILABLE components (ML weight dropped and
the rest renormalised when no model is loaded), then thresholded into
ALLOW / MONITOR / VERIFY / BLOCK.
"""
from . import anomaly, ml_model, signals, telecom_features
from .config_loader import load_config
from .risk_engine import rule_score


def _decide(score: float, cfg: dict) -> str:
    t = cfg["decision_thresholds"]
    if score <= t["allow_max"]:
        return "ALLOW"
    if score <= t["monitor_max"]:
        return "MONITOR"
    if score <= t["verify_max"]:
        return "VERIFY"
    return "BLOCK"


def score_login(attempt: dict, profile: dict) -> dict:
    """
    attempt: incoming login (current_location, imei, timestamp, login counts,
             optional telecom signals: imsi/iccid/sim_type/ip change, otp gap)
    profile: stored profile (sim_activation_date, safe_zones, known_imeis,
             last_login, account_created, num_sim_changes_last_30d, ...)
    """
    cfg = load_config()
    safe_zones = profile.get("safe_zones") or cfg["locale"]["default_safe_zones"]

    # --- Component 1: rule score --------------------------------------------
    rule = rule_score(
        profile["sim_activation_date"],
        attempt.get("current_location"),
        safe_zones,
        cfg,
    )

    # --- Component 2: behavioral signals ------------------------------------
    behav = signals.evaluate(attempt, profile, cfg)

    # --- Component 3: ML model (optional) -----------------------------------
    ml_features = telecom_features.build(attempt, profile, rule, behav)
    fraud_prob = ml_model.get_fraud_probability(ml_features)
    ml_s = None if fraud_prob is None else round(fraud_prob * 100, 1)

    # --- Component 4: unsupervised anomaly (Isolation Forest, optional) ------
    iso_prob = anomaly.get_anomaly_score(ml_features)
    iso_s = None if iso_prob is None else round(iso_prob * 100, 1)

    # --- Fusion over available components ------------------------------------
    fusion = cfg["fusion"]
    parts = [("rule_score", rule["score"]), ("behavioral_score", behav["score"])]
    if ml_s is not None:
        parts.append(("ml_score", ml_s))
    if iso_s is not None and "anomaly_score" in fusion:
        parts.append(("anomaly_score", iso_s))

    total_w = sum(fusion[name] for name, _ in parts)
    final = round(sum(fusion[name] * val for name, val in parts) / total_w, 1)
    decision = _decide(final, cfg)

    return {
        "risk_score": final,
        "decision": decision,
        "ml_used": ml_s is not None,
        "breakdown": {
            "rule": rule,
            "behavioral": behav,
            "ml": {"fraud_probability": fraud_prob, "score": ml_s,
                   "features": ml_features},
            "anomaly": {"isolation_forest_score": iso_prob, "score": iso_s},
            "fusion_weights": {name: fusion[name] for name, _ in parts},
        },
    }

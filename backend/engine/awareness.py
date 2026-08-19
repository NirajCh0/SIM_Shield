"""
User Awareness module.

  1. Plain-language education about SIM-swap fraud (served to the UI).
  2. Simulated alerting when a login is flagged VERIFY/BLOCK.

Alerts are SIMULATED only (written to data/alerts.log and returned). Nothing is
actually sent. Contact details in the alert and log are MASKED via engine.privacy
so the alert log never becomes a plaintext directory of phone numbers/emails.
"""
from datetime import datetime

from . import privacy
from .config_loader import backend_path, load_config

EDUCATION = {
    "what_is_sim_swap": (
        "A SIM swap attack is when a fraudster convinces your mobile operator "
        "(e.g. NTC, Ncell, Smart Cell) to move your phone number onto a new SIM "
        "they control. Once they have your number, the OTP your bank sends by SMS "
        "goes to the attacker instead of you - so they can log in and drain your "
        "account even though they never knew your password's second factor."
    ),
    "warning_signs": [
        "Your phone suddenly loses signal or shows 'No Service' for no reason.",
        "You stop receiving calls/SMS while others say your number rings.",
        "You get an unexpected 'SIM activated' or 'SIM change' message.",
        "Your bank app logs you out or reports a login from a new device/place.",
    ],
    "protect_yourself": [
        "Set a SIM/PIN lock and a separate account PIN with your operator.",
        "Prefer an authenticator app or hardware key over SMS OTP where possible.",
        "Never share OTPs, even with someone claiming to be from the bank or telco.",
        "If you suddenly lose mobile service, call your operator and bank at once.",
        "Enable login/transaction alerts in your banking app.",
    ],
    "if_attacked": [
        "Call your mobile operator immediately to freeze/reclaim your number.",
        "Call your bank to freeze accounts and reverse unauthorised transactions.",
        "Change your banking and email passwords from a trusted device.",
        "File a report with the Nepal Police Cyber Bureau.",
    ],
}


def get_education() -> dict:
    return EDUCATION


def explain_decision(result: dict) -> list[str]:
    """Turn a scoring result into a short, user-friendly list of reasons."""
    reasons = []
    rule = result.get("breakdown", {}).get("rule", {})
    if rule.get("days_since_sim_activation") is not None and rule["days_since_sim_activation"] <= 7:
        reasons.append(
            f"Your SIM was activated only {rule['days_since_sim_activation']} day(s) ago - "
            "recently swapped SIMs are the biggest SIM-swap red flag."
        )
    dist = rule.get("nearest_safe_zone_km")
    if dist is not None and dist > 50:
        reasons.append(f"This login is about {dist:.0f} km from your usual locations.")
    for flag in result.get("breakdown", {}).get("behavioral", {}).get("flags", []):
        reasons.append(flag["label"] + ".")
    if not reasons:
        reasons.append("No unusual signals detected on this login.")
    return reasons


def maybe_send_alert(user_id: str, result: dict, profile: dict) -> dict | None:
    """
    Simulate sending an alert (masked contact, logged) if the decision warrants
    it per config. Returns the alert payload, or None.
    """
    cfg = load_config()
    aw = cfg["awareness"]
    decision = result["decision"]
    if decision not in aw["alert_on_decision"]:
        return None

    reasons = explain_decision(result)
    contact = privacy.redact_contact(profile.get("contact", {}))
    alert = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "user_id": user_id,
        "decision": decision,
        "risk_score": result["risk_score"],
        "channels": aw["channels"],
        "to": contact,   # already masked
        "message": (
            f"SECURITY ALERT: A {decision} login attempt was detected on your "
            f"account (risk {result['risk_score']}/100). Reason: {reasons[0]} "
            "If this was not you, contact your bank and mobile operator immediately."
        ),
        "simulated": True,
    }

    log_path = backend_path(aw["alert_log"])
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(
            f"[{alert['timestamp']}] ({'/'.join(alert['channels'])}) -> "
            f"{alert['to']['phone']} / {alert['to']['email']} :: {alert['message']}\n"
        )
    return alert

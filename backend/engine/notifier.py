"""
Notification service: email / SMS / push, preference-aware.

By default every channel is SIMULATED: messages are written to the `outbox`
table (and alerts.log) so the demo can show exactly what would have been sent,
without sending anything. Recipients are always stored MASKED.

Real email (optional): set these environment variables and email switches from
'simulated' to genuinely sent via SMTP (works with Gmail app passwords):

    SIMSHIELD_SMTP_HOST=smtp.gmail.com
    SIMSHIELD_SMTP_PORT=587
    SIMSHIELD_SMTP_USER=you@gmail.com
    SIMSHIELD_SMTP_PASS=<app password>

SMS/push have no real transport in the prototype — production would use an
SMS gateway (e.g. Sparrow SMS in Nepal) and FCM/APNs. The service still
records them so the pipeline is demonstrable end-to-end.
"""
import json
import os
from datetime import datetime

from . import crypto, db, privacy, settings
from .config_loader import backend_path, load_config


def _smtp_configured() -> bool:
    return bool(os.environ.get("SIMSHIELD_SMTP_HOST") and os.environ.get("SIMSHIELD_SMTP_USER"))


def _send_real_email(to_addr: str, subject: str, body: str) -> bool:
    import smtplib
    from email.mime.text import MIMEText
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = os.environ["SIMSHIELD_SMTP_USER"]
        msg["To"] = to_addr
        with smtplib.SMTP(os.environ["SIMSHIELD_SMTP_HOST"],
                          int(os.environ.get("SIMSHIELD_SMTP_PORT", "587"))) as s:
            s.starttls()
            s.login(os.environ["SIMSHIELD_SMTP_USER"], os.environ["SIMSHIELD_SMTP_PASS"])
            s.send_message(msg)
        return True
    except Exception as e:
        print(f"[notifier] SMTP send failed ({e}); falling back to simulated outbox.")
        return False


def user_channels(user: dict) -> list[str]:
    """Channels this user has enabled in their notification preferences."""
    prefs = json.loads(user.get("prefs") or "{}")
    return [c for c in ("email", "sms", "push") if prefs.get(c, True)]


def send(user: dict, subject: str, body: str, channels: list[str] | None = None,
         alert_type: str | None = "account", severity: str = "warning",
         demo_reveal: dict | None = None) -> dict:
    """
    Deliver a notification to `user` over the requested channels (intersected
    with the user's preferences unless the caller pins specific channels, e.g.
    OTP is always email). Writes each delivery to the outbox and, if alert_type
    is given, records a dashboard alert. Returns a delivery summary.
    """
    wanted = channels or user_channels(user)
    phone = crypto.decrypt(user.get("phone_enc")) if user.get("phone_enc") else None
    deliveries = []

    for ch in wanted:
        to_masked = privacy.mask_email(user["email"]) if ch == "email" else \
                    (privacy.mask_phone(phone) if phone else "(no phone on file)")
        status = "simulated"
        if ch == "email" and _smtp_configured():
            status = "sent" if _send_real_email(user["email"], subject, body) else "simulated"
        db.execute(
            "INSERT INTO outbox (user_id, channel, to_masked, subject, body, status, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (user["id"], ch, to_masked, subject, body, status, db.now()))
        deliveries.append({"channel": ch, "to": to_masked, "status": status})

    if alert_type:
        db.add_alert(user["id"], alert_type, body, severity=severity, channels=wanted)

    # Trusted-contact out-of-band copy: on CRITICAL alerts a nominated family
    # member / friend also gets notified. If the attacker holds the victim's
    # phone AND email, this second channel is what still gets through.
    if severity == "critical" and user.get("trusted_contact_enc"):
        trusted = crypto.decrypt(user["trusted_contact_enc"])
        if trusted:
            t_masked = privacy.mask_email(trusted)
            status = "simulated"
            t_subject = f"[Trusted contact] Security alert for {user['display_name']}"
            t_body = (f"You are the trusted contact for {user['display_name']}. "
                      f"A critical security alert was just raised on their account: "
                      f"{subject}. Please check on them — their phone number may be "
                      "compromised (SIM swap).")
            if _smtp_configured():
                status = "sent" if _send_real_email(trusted, t_subject, t_body) else "simulated"
            db.execute(
                "INSERT INTO outbox (user_id, channel, to_masked, subject, body, status, created_at) "
                "VALUES (?,?,?,?,?,?,?)",
                (user["id"], "email", t_masked + " (trusted contact)", t_subject,
                 t_body, status, db.now()))
            deliveries.append({"channel": "email", "to": t_masked + " (trusted contact)",
                               "status": status})

    # legacy text log kept for parity with the detection engine's alerts.log
    log_path = backend_path(load_config()["awareness"]["alert_log"])
    with open(log_path, "a", encoding="utf-8") as f:
        stamp = datetime.now().isoformat(timespec="seconds")
        f.write(f"[{stamp}] ({'/'.join(wanted)}) -> user#{user['id']} :: {subject}: {body}\n")

    result = {"channels": deliveries, "subject": subject,
              "simulated": not _smtp_configured()}
    # OTP reveal is a DEMO-ONLY convenience and is gated on the environment, not
    # on a YAML flag (finding F7). settings.reveal_otp_enabled() is hard-wired
    # to return False in production, and the production start-up gate refuses to
    # boot if the variable is set at all — so a code can never reach an API
    # response in a real deployment.
    if demo_reveal and settings.reveal_otp_enabled() and not _smtp_configured():
        result["demo"] = demo_reveal
        result["demo_warning"] = ("One-time code revealed because this instance "
                                  "is running in demo mode. Never enable this "
                                  "outside a local demonstration.")
    return result

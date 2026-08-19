"""
Privacy-preserving utilities (data minimisation, pseudonymisation, masking).

Design principle: direct identifiers (IMEI, IMSI, ICCID, phone, email) are
sensitive. SIMShield never stores or logs them in the clear. It:

  * pseudonymises them with a salted hash for correlation (hash_id), and
  * masks them for any human-facing display (mask_phone / mask_email / mask_id).

The salt comes from the SIMSHIELD_SALT env var, falling back to the demo salt in
compliance.yaml. All behaviour here is policy-driven by compliance.yaml so the
privacy posture can change without editing code.
"""
import hashlib
import hmac

from . import settings
from .config_loader import load_compliance


def hash_id(value: str) -> str:
    """
    Keyed pseudonym for an identifier: HMAC-SHA-256 under a high-entropy secret,
    truncated to 32 hex characters (128 bits).

    Two earlier weaknesses are fixed here (findings F9 and F11):

      * The salt was a *public default* committed in compliance.yaml. Anyone
        with the repository could re-identify every audit record by hashing
        candidate phone numbers — the identifier space is tiny (a Nepali mobile
        number is ~8 unknown digits), so an unkeyed salted hash is not a
        pseudonym at all, it is an index.
      * The output was truncated to 16 hex (64 bits), which invites collisions
        and makes brute force cheaper still.

    HMAC under `SIMSHIELD_PSEUDONYM_SECRET` means an attacker holding the
    database and the source still cannot reverse the mapping without the secret,
    which lives only in the environment.

    Changing the secret intentionally breaks correlation with previously written
    audit records; that is the documented trade-off of rotating it.
    """
    if value is None:
        return None
    key = settings.pseudonym_secret().encode("utf-8")
    digest = hmac.new(key, str(value).encode("utf-8"), hashlib.sha256).hexdigest()
    return f"hmac-sha256:{digest[:32]}"


def mask_phone(phone: str) -> str:
    """+9779812345678 -> +9779812***678 (keep country + last 3)."""
    if not phone:
        return phone
    digits = [c for c in phone if c.isdigit()]
    if len(digits) < 5:
        return "***"
    keep_front, keep_back = phone[:6], phone[-3:]
    return f"{keep_front}***{keep_back}"


def mask_email(email: str) -> str:
    """alice.karki@example.np -> a***@example.np."""
    if not email or "@" not in email:
        return email
    local, domain = email.split("@", 1)
    head = local[0] if local else "*"
    return f"{head}***@{domain}"


def mask_id(value: str, keep: int = 4) -> str:
    """359881030314159 -> ***********4159 (mask all but the last `keep`)."""
    if not value:
        return value
    s = str(value)
    if len(s) <= keep:
        return "*" * len(s)
    return "*" * (len(s) - keep) + s[-keep:]


def minimise_attempt(attempt: dict) -> dict:
    """
    Return only the attempt fields the policy allows to be persisted. Raw
    identifiers and (if configured) raw GPS are dropped - a log should never be
    a second copy of the sensitive input.
    """
    cfg = load_compliance()["privacy"]
    allowed = set(cfg["loggable_attempt_fields"])
    out = {k: v for k, v in attempt.items() if k in allowed}
    return out


def redact_contact(contact: dict) -> dict:
    """Mask a profile's contact block for safe display/return."""
    if not contact:
        return {}
    return {
        "phone": mask_phone(contact.get("phone", "")),
        "email": mask_email(contact.get("email", "")),
    }

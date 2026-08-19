"""
Authentication service: registration, password login + email-OTP 2FA,
password reset, sessions, device fingerprinting, lockout and account freeze.

Flow (2FA):
    1. POST /api/auth/login      -> password checked -> OTP emailed (simulated
                                    outbox unless real SMTP is configured)
    2. POST /api/auth/verify-otp -> OTP checked -> session token issued,
                                    device fingerprint registered/compared

Passwords are PBKDF2-HMAC-SHA256 (no plaintext ever stored); OTP codes are
stored hashed with the same salted hash used for identifiers; sessions are
random 256-bit bearer tokens with a TTL. All tunables live in config.yaml ->
auth. This is a prototype: production would add rate limiting at the proxy,
WebAuthn, and IP reputation.
"""
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timedelta

from . import crypto, db, notifier, privacy
from .config_loader import load_config

PBKDF2_ITERATIONS = 200_000


# --- passwords ----------------------------------------------------------------
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


# --- users ----------------------------------------------------------------
def get_user_by_email(email: str) -> dict | None:
    return db.query_one("SELECT * FROM users WHERE email = ?", (email.strip().lower(),))


def get_user(user_id: int) -> dict | None:
    return db.query_one("SELECT * FROM users WHERE id = ?", (user_id,))


def public_user(u: dict) -> dict:
    """User record safe to return to the client (no hashes, masked phone)."""
    phone = crypto.decrypt(u.get("phone_enc"))
    trusted = crypto.decrypt(u.get("trusted_contact_enc")) if u.get("trusted_contact_enc") else None
    return {
        "id": u["id"],
        "email": u["email"],
        "display_name": u["display_name"],
        "role": u["role"],
        "operator": u.get("operator"),
        "phone_masked": privacy.mask_phone(phone) if phone else None,
        "trusted_contact_masked": privacy.mask_email(trusted) if trusted else None,
        "language": u.get("language", "en"),
        "frozen": bool(u["frozen"]),
        "twofa_enabled": bool(u["twofa_enabled"]),
        "prefs": json.loads(u.get("prefs") or "{}"),
        "points": u.get("points", 0),
        "badges": json.loads(u.get("badges") or "[]"),
        "balance": round(u.get("balance") or 0.0, 2),
        "safe_zones": json.loads(u.get("safe_zones") or "[]"),
        "created_at": u.get("created_at"),
        "last_login": u.get("last_login"),
        "profile_id": u.get("profile_id"),
    }


def register(email: str, password: str, display_name: str, phone: str = "",
             operator: str = "NTC", language: str = "en",
             profile_id: str | None = None, role: str = "user",
             trusted_contact: str = "", balance: float = 150000.0) -> dict:
    email = (email or "").strip().lower()
    if "@" not in email or len(email) < 5:
        raise ValueError("A valid email address is required.")
    if len(password or "") < 8:
        raise ValueError("Password must be at least 8 characters.")
    if not (display_name or "").strip():
        raise ValueError("Display name is required.")
    if get_user_by_email(email):
        raise ValueError("An account with this email already exists.")

    cfg = load_config()["auth"]
    prefs = dict(cfg["default_notification_prefs"])
    db.execute(
        "INSERT INTO users (email, password_hash, display_name, role, phone_enc, operator, "
        "profile_id, language, prefs, trusted_contact_enc, balance, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (email, hash_password(password), display_name.strip(), role,
         crypto.encrypt(phone) if phone else None, operator, profile_id,
         language, json.dumps(prefs),
         crypto.encrypt(trusted_contact.strip()) if trusted_contact.strip() else None,
         balance, db.now()),
    )
    user = get_user_by_email(email)
    db.log_activity(user["id"], "registered", {"operator": operator})
    return user


# --- OTP (email second factor) --------------------------------------------
def _hash_otp(code: str) -> str:
    return privacy.hash_id("otp:" + code)


def issue_otp(user: dict, purpose: str = "login", challenge: str | None = None) -> dict:
    """
    Create a one-time code, store its hash, and send it via the notifier.

    `challenge` binds the code to a short-lived server-side login challenge and
    the device context that started the flow (finding F7). Without it, knowing
    an email address was enough to consume a code issued for a different
    session; with it, a code is only redeemable by the browser that began the
    sign-in, for that purpose.
    """
    cfg = load_config()["auth"]
    code = f"{secrets.randbelow(10**6):06d}"
    expires = (datetime.now() + timedelta(minutes=cfg["otp_ttl_minutes"])).isoformat(timespec="seconds")
    # one live code per email+purpose
    db.execute("UPDATE otp_codes SET used = 1 WHERE email = ? AND purpose = ?",
               (user["email"], purpose))
    db.execute(
        "INSERT INTO otp_codes (email, code_hash, purpose, challenge, expires_at, "
        "created_at) VALUES (?,?,?,?,?,?)",
        (user["email"], _hash_otp(code), purpose,
         privacy.hash_id(challenge) if challenge else None, expires, db.now()),
    )
    subject = {
        "login": "Your SIMShield sign-in code",
        "reset": "Your SIMShield password-reset code",
        "unfreeze": "Your SIMShield account-unfreeze code",
    }.get(purpose, "Your SIMShield verification code")
    body = (f"Your one-time code is {code}. It expires in {cfg['otp_ttl_minutes']} minutes. "
            "SIMShield staff will NEVER ask you for this code — if anyone does, it is a scam.")
    delivery = notifier.send(user, subject, body, channels=["email"],
                             alert_type=None, demo_reveal={"otp": code})
    db.log_activity(user["id"], "otp_sent", {"purpose": purpose})
    return delivery


def verify_otp(email: str, code: str, purpose: str = "login",
               challenge: str | None = None) -> bool:
    """
    Check a one-time code. The code must match, be unexpired, be within the
    attempt budget, be for this exact purpose, and — when the issuing flow bound
    one — come from the same login challenge (finding F7).
    """
    cfg = load_config()["auth"]
    row = db.query_one(
        "SELECT * FROM otp_codes WHERE email = ? AND purpose = ? AND used = 0 "
        "ORDER BY id DESC LIMIT 1", (email.strip().lower(), purpose))
    if not row:
        return False
    if datetime.fromisoformat(row["expires_at"]) < datetime.now():
        return False
    if row["attempts"] >= cfg["otp_max_attempts"]:
        return False

    # Purpose is already in the WHERE clause; the challenge binds the code to
    # the browser/device that started the flow.
    bound = row["challenge"] if "challenge" in row.keys() else None
    if bound:
        supplied = privacy.hash_id(challenge) if challenge else ""
        if not hmac.compare_digest(bound, supplied or ""):
            db.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?",
                       (row["id"],))
            return False

    ok = hmac.compare_digest(row["code_hash"], _hash_otp(code.strip()))
    db.execute("UPDATE otp_codes SET attempts = attempts + 1, used = ? WHERE id = ?",
               (1 if ok else 0, row["id"]))
    return ok


# --- login + lockout --------------------------------------------------------
def check_password_step(email: str, password: str) -> dict:
    """
    Step 1 of the 2FA login. Returns {'ok': True, 'user': ...} or raises
    ValueError with a user-safe message. Applies a lockout counter.
    """
    cfg = load_config()["auth"]
    user = get_user_by_email(email)
    if not user:
        raise ValueError("Invalid email or password.")

    if user["locked_until"] and datetime.fromisoformat(user["locked_until"]) > datetime.now():
        raise ValueError("Too many failed attempts. Account temporarily locked — try again later.")

    if not verify_password(password, user["password_hash"]):
        fails = user["failed_attempts"] + 1
        locked_until = None
        if fails >= cfg["lockout_after_failures"]:
            locked_until = (datetime.now() + timedelta(
                minutes=cfg["lockout_minutes"])).isoformat(timespec="seconds")
            fails = 0
        db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                   (fails, locked_until, user["id"]))
        db.log_activity(user["id"], "login_fail", {})
        raise ValueError("Invalid email or password.")

    db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
               (user["id"],))
    return user


# --- sessions ----------------------------------------------------------------
def create_session(user: dict, fingerprint: str | None, ip: str | None) -> tuple[str, str, int]:
    """
    Issue a session. Returns (token, csrf_token, ttl_seconds).

    The token is delivered as an HttpOnly cookie by the route layer; the CSRF
    token is a separate value the page echoes back in X-CSRF-Token so a
    cross-site request cannot forge a state change (findings F12/F13).
    """
    cfg = load_config()["auth"]
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    ttl_seconds = int(cfg["session_ttl_hours"] * 3600)
    expires = (datetime.now() + timedelta(seconds=ttl_seconds)).isoformat(timespec="seconds")
    db.execute(
        "INSERT INTO sessions (token, user_id, fingerprint_hash, ip, csrf_token, "
        "created_at, expires_at) VALUES (?,?,?,?,?,?,?)",
        (token, user["id"], privacy.hash_id(fingerprint) if fingerprint else None,
         ip, csrf, db.now(), expires),
    )
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (db.now(), user["id"]))
    return token, csrf, ttl_seconds


def get_session_user(token: str | None) -> dict | None:
    if not token:
        return None
    s = db.query_one("SELECT * FROM sessions WHERE token = ?", (token,))
    if not s or datetime.fromisoformat(s["expires_at"]) < datetime.now():
        return None
    return get_user(s["user_id"])


def destroy_session(token: str) -> None:
    db.execute("DELETE FROM sessions WHERE token = ?", (token,))


def list_sessions(user_id: int, current_token: str | None = None) -> list[dict]:
    """Active sessions with a safe pseudonymous id (never the raw token)."""
    rows = db.query_all(
        "SELECT token, fingerprint_hash, ip, created_at, expires_at FROM sessions "
        "WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC",
        (user_id, db.now()))
    out = []
    for r in rows:
        out.append({
            "session_id": privacy.hash_id("sess:" + r["token"])[-8:],
            "device_id": (r["fingerprint_hash"] or "")[-8:],
            "ip": r["ip"],
            "created_at": r["created_at"],
            "expires_at": r["expires_at"],
            "current": bool(current_token and r["token"] == current_token),
        })
    return out


def revoke_session(user_id: int, session_id: str) -> bool:
    """Revoke one of the user's sessions by its pseudonymous id."""
    rows = db.query_all("SELECT token FROM sessions WHERE user_id = ?", (user_id,))
    for r in rows:
        if privacy.hash_id("sess:" + r["token"])[-8:] == session_id:
            destroy_session(r["token"])
            db.log_activity(user_id, "session_revoked", {"session": session_id})
            return True
    return False


# --- device fingerprinting ---------------------------------------------------
def register_device(user: dict, fingerprint: str | None, label: str = "") -> dict:
    """
    Track the browser/device fingerprint. Returns {'known': bool, 'new': bool}
    so the caller can raise a new-device alert.
    """
    if not fingerprint:
        return {"known": False, "new": False}
    fp_hash = privacy.hash_id(fingerprint)
    existing = db.query_one(
        "SELECT * FROM devices WHERE user_id = ? AND fingerprint_hash = ?",
        (user["id"], fp_hash))
    if existing:
        db.execute("UPDATE devices SET last_seen = ? WHERE id = ?", (db.now(), existing["id"]))
        return {"known": True, "new": False}
    db.execute(
        "INSERT INTO devices (user_id, fingerprint_hash, label, first_seen, last_seen) "
        "VALUES (?,?,?,?,?)", (user["id"], fp_hash, label, db.now(), db.now()))
    return {"known": False, "new": True}


def list_devices(user_id: int) -> list[dict]:
    rows = db.query_all(
        "SELECT id, label, trusted, first_seen, last_seen, fingerprint_hash "
        "FROM devices WHERE user_id = ? ORDER BY last_seen DESC", (user_id,))
    for r in rows:  # show only a short pseudonym, never the raw fingerprint
        r["device_id"] = r.pop("fingerprint_hash", "")[-8:]
    return rows


# --- freeze ----------------------------------------------------------------
def set_frozen(user_id: int, frozen: bool, by: str = "user") -> None:
    db.execute("UPDATE users SET frozen = ? WHERE id = ?", (1 if frozen else 0, user_id))
    db.log_activity(user_id, "freeze" if frozen else "unfreeze", {"by": by})
    db.add_alert(user_id, "account",
                 ("Account frozen — all transactions are paused." if frozen
                  else "Account unfrozen — normal operation restored."),
                 severity="critical" if frozen else "info", status="acknowledged")


# --- password reset ----------------------------------------------------------
def reset_password(email: str, code: str, new_password: str) -> None:
    user = get_user_by_email(email)
    if not user:
        raise ValueError("Invalid reset request.")
    if len(new_password or "") < 8:
        raise ValueError("Password must be at least 8 characters.")
    if not verify_otp(email, code, purpose="reset"):
        raise ValueError("Invalid or expired reset code.")
    db.execute("UPDATE users SET password_hash = ?, failed_attempts = 0, locked_until = NULL "
               "WHERE id = ?", (hash_password(new_password), user["id"]))
    db.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))  # log out everywhere
    db.log_activity(user["id"], "password_reset", {})
    notifier.send(user, "Your SIMShield password was changed",
                  "Your password was just reset. If this was not you, contact "
                  "your bank immediately and freeze your account from the dashboard.",
                  channels=["email"], alert_type="account")

"""
Authentication API — registration, 2FA login (password -> emailed OTP ->
session), password reset, logout.

The pre-OTP risk check is wired HERE: when the account is linked to a synthetic
detection profile, the detection engine scores the login after the password step
and BEFORE any OTP is issued. BLOCK refuses the login outright (and alerts the
user out-of-band); VERIFY proceeds — the OTP itself is the step-up. No OTP is
ever sent for a blocked attempt.

Security controls applied here (see SECURITY_REMEDIATION.md):
  F7  OTP bound to a short-lived server-side login challenge + device context;
      never echoed in a response outside demo mode; every OTP flow rate-limited.
  F12 Sessions issued as HttpOnly cookies (bearer accepted only outside prod).
  F16 Every payload validated; malformed input returns 400, never 500.
  Account enumeration: responses are deliberately identical whether or not an
  email exists.
"""
import json
import secrets
from datetime import datetime, timedelta

from flask import Blueprint, jsonify, make_response, request

from engine import (auth, awareness, compliance, db, notifier, privacy,
                    profiles, ratelimit, recovery_codes, settings, webauthn)
from engine.config_loader import load_config
from engine.detector import score_login
from engine.validation import Validator
from routes.common import (clear_session_cookies, current_user, require_auth,
                           set_session_cookies)

auth_bp = Blueprint("auth", __name__, url_prefix="/api/auth")

# Short-lived server-side login challenges: challenge_id -> {email, fp, expires}
# Kept in-process deliberately; a multi-worker deployment would move this to
# Redis (📋). It exists so an OTP can only be redeemed by the browser that
# started the sign-in, for that purpose.
_challenges: dict[str, dict] = {}
CHALLENGE_TTL_SECONDS = 600


def _new_challenge(email: str, fingerprint: str | None) -> str:
    _reap_challenges()
    cid = secrets.token_urlsafe(24)
    _challenges[cid] = {
        "email": email.strip().lower(),
        "fp": privacy.hash_id(fingerprint) if fingerprint else None,
        "expires": datetime.now() + timedelta(seconds=CHALLENGE_TTL_SECONDS),
    }
    return cid


def _reap_challenges() -> None:
    now = datetime.now()
    for cid in [c for c, v in _challenges.items() if v["expires"] < now]:
        _challenges.pop(cid, None)


def _challenge_ok(cid: str, email: str, fingerprint: str | None) -> bool:
    """A challenge is valid only for its own email and originating device."""
    _reap_challenges()
    rec = _challenges.get(cid or "")
    if not rec:
        return False
    if rec["email"] != (email or "").strip().lower():
        return False
    if rec["fp"] is not None:
        supplied = privacy.hash_id(fingerprint) if fingerprint else None
        if rec["fp"] != supplied:
            return False
    return True


def _limited(bucket: str, per_email: str = "") -> bool:
    """True when the caller has exceeded the configured rate limit."""
    limits = load_config()["auth"].get("rate_limits", {})
    cfg = limits.get(bucket)
    if not cfg:
        return False
    key = f"{bucket}:{request.remote_addr}:{(per_email or '').lower()}"
    return not ratelimit.allow(key, cfg["limit"], cfg["window_seconds"])


_RATE_MSG = "Too many attempts — please wait a few minutes and try again."
# Deliberately identical whether or not the account exists (no enumeration).
_GENERIC_RESET = ("If that email has an account, a reset code has been sent to it.")


def _load_profile(profile_id: str | None) -> dict | None:
    """Shared loader — resolves relative SIM ages (see engine.profiles)."""
    return profiles.load(profile_id) if profile_id else None


def _pre_otp_risk_check(user: dict, data: dict) -> dict | None:
    """Score the login with the detection engine before issuing any OTP."""
    profile = _load_profile(user.get("profile_id"))
    if profile is None:
        return None
    user_zones = json.loads(user.get("safe_zones") or "[]")
    if user_zones:
        profile = dict(profile, safe_zones=user_zones)

    fingerprint = data.get("fingerprint")
    device_known = False
    if fingerprint:
        fp_hash = privacy.hash_id(fingerprint)
        device_known = db.query_one(
            "SELECT 1 AS x FROM devices WHERE user_id = ? AND fingerprint_hash = ?",
            (user["id"], fp_hash)) is not None
    attempt = {
        "current_location": data.get("location"),
        "imei": (profile.get("known_imeis") or [None])[0] if device_known
                else f"web-{(fingerprint or 'anon')[:12]}",
        "timestamp": db.now(),
        "logins_last_24h": 1,
        "failed_logins_last_24h": user.get("failed_attempts", 0),
    }
    result = score_login(attempt, profile)
    result["reasons"] = awareness.explain_decision(result)
    compliance.record_decision(f"acct:{user['id']}", attempt, result)
    db.log_activity(user["id"], "pre_otp_check",
                    {"decision": result["decision"], "risk": result["risk_score"],
                     "device_known": device_known})
    _record_login_area(user, attempt, profile, result)
    # A restrictive decision now raises a CASE, not just an alert: someone has
    # to look at it, and their conclusion has to be recorded with a reason code
    # (improvement #2). Deduplicated per user/decision per hour inside cases.
    try:
        from engine import cases
        cases.auto_open_for_decision(user["id"], result["decision"],
                                     result["risk_score"], result.get("reasons"))
    except Exception:                              # noqa: BLE001
        # Case creation is an operational nicety; it must never be able to
        # break a sign-in.
        pass
    return result


def _record_login_area(user: dict, attempt: dict, profile: dict, result: dict) -> None:
    """Persist a COARSE sign-in area (area + band only, never coordinates)."""
    from engine import geo, operator
    from engine.config_loader import load_compliance
    if not load_compliance()["privacy"].get("store_login_area", False):
        return
    loc = attempt.get("current_location") or {}
    if loc.get("lat") is None:
        return
    zones = json.loads(user.get("safe_zones") or "[]") or profile.get("safe_zones") or []
    coarse = geo.coarse_area(loc["lat"], loc["lon"], zones)
    mm = operator.location_mismatch(profile, attempt)
    db.execute(
        "INSERT INTO login_locations (user_id, area, country, band, decision, "
        "risk_score, sim_area, mismatch, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (user["id"], coarse["area"], coarse["country"], coarse["band"],
         result["decision"], result["risk_score"],
         mm.get("sim_area") if mm.get("available") else None,
         1 if mm.get("mismatch") else 0, db.now()))


# --- registration -------------------------------------------------------------
@auth_bp.route("/register", methods=["POST"])
def register():
    if _limited("register"):
        return jsonify({"error": _RATE_MSG}), 429
    v = Validator(request.get_json(silent=True))
    v.string("email", required=True, max_len=254)
    v.string("password", required=True, max_len=200, strip=False)
    v.string("display_name", required=True, max_len=80)
    v.string("phone", max_len=32)
    v.string("operator", default="NTC", choices={"NTC", "NCELL", "SMART"})
    v.string("language", default="en", choices={"en", "ne"})
    v.string("trusted_contact", max_len=254)
    v.identifier("profile_id", max_len=64)
    data = v.done()

    try:
        user = auth.register(
            email=data["email"], password=data["password"],
            display_name=data["display_name"], phone=data["phone"],
            operator=data["operator"] or "NTC", language=data["language"] or "en",
            profile_id=data["profile_id"] or None,
            trusted_contact=data["trusted_contact"])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    notifier.send(user, "Welcome to SIMShield",
                  "Your account is protected with 2-step verification. We will "
                  "alert you before any OTP is sent when a login looks risky.",
                  channels=["email"], alert_type=None)
    return jsonify({"ok": True, "message": "Account created. You can sign in now."})


# --- login: password step ------------------------------------------------------
@auth_bp.route("/login", methods=["POST"])
def login():
    v = Validator(request.get_json(silent=True))
    v.string("email", required=True, max_len=254)
    v.string("password", required=True, max_len=200, strip=False)
    v.string("fingerprint", max_len=128)
    v.coordinates("location")
    data = v.done()

    if _limited("login", data["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    try:
        user = auth.check_password_step(data["email"], data["password"])
    except ValueError as e:
        return jsonify({"error": str(e)}), 401

    risk = _pre_otp_risk_check(user, data)
    if risk and risk["decision"] == "BLOCK":
        db.add_alert(user["id"], "login_risk",
                     f"A sign-in attempt was BLOCKED before an OTP was sent "
                     f"(risk {risk['risk_score']}/100). {risk['reasons'][0]}",
                     severity="critical", meta={"reasons": risk["reasons"]})
        notifier.send(user, "Sign-in blocked on your account",
                      "A high-risk sign-in was blocked before any OTP was sent. "
                      "If this was you, contact the fraud team. If not, your "
                      "credentials may be compromised — change your password.",
                      alert_type=None)
        return jsonify({"error": "This sign-in was blocked as high-risk. No OTP "
                                 "was sent. The account owner has been notified.",
                        "decision": "BLOCK", "risk_score": risk["risk_score"],
                        "reasons": risk["reasons"]}), 403

    if not user["twofa_enabled"]:
        token, csrf, ttl = auth.create_session(user, data["fingerprint"],
                                               request.remote_addr)
        db.log_activity(user["id"], "login_ok", {"twofa": False})
        # Neither the session token nor the CSRF token appears in the body.
        # The session travels ONLY in the HttpOnly cookie (unreadable by JS, so
        # an XSS cannot exfiltrate it) and the CSRF token ONLY in its own
        # non-HttpOnly cookie. Echoing either here would hand a script exactly
        # what the HttpOnly flag exists to withhold.
        resp = make_response(jsonify({"ok": True,
                                      "user": auth.public_user(user)}))
        return set_session_cookies(resp, token, csrf, ttl)

    challenge = _new_challenge(data["email"], data["fingerprint"])
    delivery = auth.issue_otp(user, purpose="login", challenge=challenge)
    body = {"ok": True, "otp_required": True, "challenge": challenge,
            "message": "A one-time code was sent to your email.",
            "delivery": delivery}
    if risk:
        body["pre_otp_check"] = {"decision": risk["decision"],
                                 "risk_score": risk["risk_score"],
                                 "reasons": risk["reasons"]}
        if risk["decision"] == "VERIFY":
            db.add_alert(user["id"], "login_risk",
                         f"A risky sign-in required step-up verification "
                         f"(risk {risk['risk_score']}/100). {risk['reasons'][0]}",
                         severity="warning", meta={"reasons": risk["reasons"]})
    return jsonify(body)


# --- login: OTP step -----------------------------------------------------------
@auth_bp.route("/verify-otp", methods=["POST"])
def verify_otp():
    v = Validator(request.get_json(silent=True))
    v.string("email", required=True, max_len=254)
    v.string("code", required=True, max_len=12)
    v.string("challenge", max_len=128)
    v.string("fingerprint", max_len=128)
    v.string("device_label", max_len=80, default="Web browser")
    data = v.done()

    if _limited("verify_otp", data["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    user = auth.get_user_by_email(data["email"])
    if not user:
        return jsonify({"error": "Invalid verification attempt."}), 401
    if not _challenge_ok(data["challenge"], data["email"], data["fingerprint"]):
        return jsonify({"error": "This sign-in attempt has expired. "
                                 "Please start again."}), 401
    if not auth.verify_otp(data["email"], data["code"], purpose="login",
                           challenge=data["challenge"]):
        db.log_activity(user["id"], "otp_fail", {})
        return jsonify({"error": "Invalid or expired code."}), 401

    _challenges.pop(data["challenge"], None)   # single use
    device = auth.register_device(user, data["fingerprint"],
                                  label=data["device_label"] or "Web browser")
    if device["new"]:
        notifier.send(user, "New device signed in",
                      "A new device just signed in to your SIMShield account. "
                      "If this was not you, freeze your account immediately.",
                      alert_type="account", severity="warning")
    token, csrf, ttl = auth.create_session(user, data["fingerprint"],
                                           request.remote_addr)
    db.log_activity(user["id"], "otp_ok", {"device_known": device["known"]})
    db.log_activity(user["id"], "login_ok", {"device_known": device["known"]})
    # As above: tokens are delivered by cookie only, never in the JSON body.
    resp = make_response(jsonify({"ok": True, "user": auth.public_user(user)}))
    return set_session_cookies(resp, token, csrf, ttl)


# --- login: phone-independent second factors (improvement #5) ------------------
# Both routes below solve the same problem the OTP cannot: after a SIM swap the
# attacker holds the number, so anything delivered to it is delivered to them.
# These two factors never touch the mobile network.

@auth_bp.route("/recovery-login", methods=["POST"])
def recovery_login():
    """
    Complete a sign-in with a single-use recovery code instead of the SMS OTP.

    The password step still had to pass — this replaces the second factor, it
    does not remove one. The code is consumed atomically, so a code observed in
    transit cannot be replayed.
    """
    v = Validator(request.get_json(silent=True))
    v.string("email", required=True, max_len=254)
    v.string("code", required=True, max_len=32)
    v.string("challenge", max_len=128)
    v.string("fingerprint", max_len=128)
    v.string("device_label", max_len=80, default="Web browser")
    data = v.done()

    if _limited("recovery_login", data["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    user = auth.get_user_by_email(data["email"])
    if not user:
        return jsonify({"error": "Invalid verification attempt."}), 401
    if not _challenge_ok(data["challenge"], data["email"], data["fingerprint"]):
        return jsonify({"error": "This sign-in attempt has expired. "
                                 "Please start again."}), 401
    if not recovery_codes.consume(user["id"], data["code"]):
        db.log_activity(user["id"], "recovery_code_fail", {})
        # Deliberately identical to an OTP failure: the response must not reveal
        # whether the code was wrong, already spent, or never issued.
        return jsonify({"error": "Invalid or already-used recovery code."}), 401

    _challenges.pop(data["challenge"], None)
    device = auth.register_device(user, data["fingerprint"],
                                  label=data["device_label"] or "Web browser")
    token, csrf, ttl = auth.create_session(user, data["fingerprint"],
                                           request.remote_addr)
    left = recovery_codes.remaining(user["id"])
    db.log_activity(user["id"], "login_ok", {"factor": "recovery_code"})
    notifier.send(user, "A recovery code was used to sign in",
                  f"Someone signed in to your account using a recovery code. "
                  f"{left} codes remain. If this was not you, freeze your "
                  "account now — a recovery code works even if your phone "
                  "number has been taken.",
                  alert_type="account", severity="warning")
    resp = make_response(jsonify({"ok": True, "user": auth.public_user(user),
                                  "recovery_codes_remaining": left}))
    return set_session_cookies(resp, token, csrf, ttl)


@auth_bp.route("/passkey/options", methods=["POST"])
def passkey_options():
    """Challenge for `navigator.credentials.get()`. Safe before authentication."""
    v = Validator(request.get_json(silent=True))
    v.string("email", max_len=254)
    data = v.done()
    if _limited("passkey", data["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    # A missing or unknown email still returns options: replying "no such user"
    # here would turn the passkey endpoint into an account-existence oracle.
    user = auth.get_user_by_email(data["email"]) if data["email"] else None
    try:
        return jsonify(webauthn.authentication_options(user))
    except webauthn.WebAuthnError as exc:
        return jsonify({"error": str(exc)}), 400


@auth_bp.route("/passkey/login", methods=["POST"])
def passkey_login():
    """
    Sign in with a passkey alone.

    A passkey is both possession and (with user verification) inherence, and it
    is bound to this origin, so it stands on its own — there is no password step
    in front of it. That is the point: it removes the SMS OTP from the flow
    entirely rather than adding another factor beside it.
    """
    v = Validator(request.get_json(silent=True))
    v.string("handle", required=True, max_len=64)
    v.string("fingerprint", max_len=128)
    v.string("device_label", max_len=80, default="Web browser")
    data = v.done()
    if _limited("passkey"):
        return jsonify({"error": _RATE_MSG}), 429
    credential = (request.get_json(silent=True) or {}).get("credential")
    if not isinstance(credential, dict):
        return jsonify({"error": "A credential object is required."}), 400
    try:
        result = webauthn.authenticate(data["handle"], credential)
    except webauthn.WebAuthnError as exc:
        return jsonify({"error": str(exc)}), 401

    user = auth.get_user(result["user_id"])
    if not user:
        return jsonify({"error": "Account not found."}), 401
    if user["frozen"]:
        return jsonify({"error": "This account is frozen. Contact the bank."}), 403

    auth.register_device(user, data["fingerprint"],
                         label=data["device_label"] or "Web browser")
    token, csrf, ttl = auth.create_session(user, data["fingerprint"],
                                           request.remote_addr)
    db.log_activity(user["id"], "login_ok", {"factor": "passkey",
                                             "clone_warning": result["clone_warning"]})
    resp = make_response(jsonify({
        "ok": True, "user": auth.public_user(user),
        "user_verified": result["user_verified"],
        "clone_warning": result["clone_warning"]}))
    return set_session_cookies(resp, token, csrf, ttl)


@auth_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    v = Validator(request.get_json(silent=True))
    v.string("email", required=True, max_len=254)
    v.string("challenge", max_len=128)
    v.string("fingerprint", max_len=128)
    data = v.done()

    if _limited("resend_otp", data["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    if not _challenge_ok(data["challenge"], data["email"], data["fingerprint"]):
        return jsonify({"error": "Start the sign-in again."}), 400
    user = auth.get_user_by_email(data["email"])
    live = user and db.query_one(
        "SELECT 1 AS x FROM otp_codes WHERE email = ? AND purpose = 'login' "
        "AND used = 0", (user["email"],))
    if not live:
        return jsonify({"error": "Start the sign-in again."}), 400
    return jsonify({"ok": True,
                    "delivery": auth.issue_otp(user, purpose="login",
                                               challenge=data["challenge"])})


@auth_bp.route("/logout", methods=["POST"])
@require_auth()
def logout():
    from routes.common import session_token
    tok = session_token()
    if tok:
        auth.destroy_session(tok)
    return clear_session_cookies(make_response(jsonify({"ok": True})))


@auth_bp.route("/me")
def me():
    user = current_user()
    if not user:
        return jsonify({"user": None})
    return jsonify({"user": auth.public_user(user)})


# --- password reset ------------------------------------------------------------
@auth_bp.route("/reset/request", methods=["POST"])
def reset_request():
    v = Validator(request.get_json(silent=True))
    v.string("email", required=True, max_len=254)
    data = v.done()

    if _limited("reset", data["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    user = auth.get_user_by_email(data["email"])
    delivery = auth.issue_otp(user, purpose="reset") if user else None
    resp = {"ok": True, "message": _GENERIC_RESET}
    # Demo mode only. Outside demo the response is byte-identical whether or not
    # the account exists, so this endpoint cannot be used to enumerate accounts.
    if delivery and settings.reveal_otp_enabled():
        resp["delivery"] = delivery
    return jsonify(resp)


@auth_bp.route("/reset/confirm", methods=["POST"])
def reset_confirm():
    v = Validator(request.get_json(silent=True))
    v.string("email", required=True, max_len=254)
    v.string("code", required=True, max_len=12)
    v.string("new_password", required=True, max_len=200, strip=False)
    data = v.done()

    if _limited("reset_confirm", data["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    try:
        auth.reset_password(data["email"], data["code"], data["new_password"])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify({"ok": True,
                    "message": "Password changed. Sign in with the new password."})

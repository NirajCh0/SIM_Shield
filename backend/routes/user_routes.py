"""
Signed-in user API: dashboard (risk score, alerts, activity, SIM events,
transactions, devices), notification preferences, account freeze/unfreeze
(OTP-gated), transaction simulation, security checklist gamification, and a
demo SIM-swap event injector so the full alert pipeline can be demonstrated.
"""
import json

from flask import Blueprint, g, jsonify, request

from engine import (account_risk, appeals, auth, db, gamification, notifier,
                    playbook, privacy, ratelimit, recovery_codes, transactions,
                    webauthn)
from engine.config_loader import load_config
from engine.validation import Validator
from routes.common import require_auth

user_bp = Blueprint("user", __name__, url_prefix="/api/me")

_RATE_MSG = "Too many attempts — please wait a few minutes and try again."


def _limited(bucket: str, per_email: str = "") -> bool:
    """Rate-limit an OTP-issuing or OTP-consuming flow (finding F7)."""
    cfg = load_config()["auth"].get("rate_limits", {}).get(bucket)
    if not cfg:
        return False
    key = f"{bucket}:{request.remote_addr}:{(per_email or '').lower()}"
    return not ratelimit.allow(key, cfg["limit"], cfg["window_seconds"])


@user_bp.route("/dashboard")
@require_auth()
def dashboard():
    u = g.user
    alerts = db.query_all(
        "SELECT * FROM alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 20",
        (u["id"],))
    for a in alerts:
        a["meta"] = json.loads(a["meta"] or "{}")
        a["channels"] = json.loads(a["channels"] or "[]")
    activity = db.query_all(
        "SELECT action, meta, created_at FROM activity_log WHERE user_id = ? "
        "ORDER BY id DESC LIMIT 25", (u["id"],))
    for row in activity:
        row["meta"] = json.loads(row["meta"] or "{}")
    sim_events = db.query_all(
        "SELECT event_type, operator, risk_score, details, occurred_at "
        "FROM sim_events WHERE user_id = ? ORDER BY occurred_at DESC LIMIT 10",
        (u["id"],))
    risk = account_risk.compute(u)
    account_risk.snapshot(u["id"], risk)
    # Coarse sign-in locations — area + distance band only, never coordinates.
    login_locations = db.query_all(
        "SELECT area, country, band, decision, risk_score, sim_area, mismatch, "
        "created_at FROM login_locations WHERE user_id = ? "
        "ORDER BY id DESC LIMIT 15", (u["id"],))
    from flask import request as _rq
    token = _rq.headers.get("Authorization", "")[len("Bearer "):]
    return jsonify({
        "user": auth.public_user(u),
        "risk": risk,
        "risk_history": account_risk.history(u["id"]),
        "alerts": alerts,
        "activity": activity,
        "sim_events": sim_events,
        "login_locations": login_locations,
        "transactions": transactions.list_for_user(u["id"], limit=10),
        "devices": auth.list_devices(u["id"]),
        "sessions": auth.list_sessions(u["id"], current_token=token),
        "badge_catalog": gamification.badge_catalog(),
    })


@user_bp.route("/alerts/<int:alert_id>/ack", methods=["POST"])
@require_auth()
def ack_alert(alert_id: int):
    row = db.query_one("SELECT * FROM alerts WHERE id = ? AND user_id = ?",
                       (alert_id, g.user["id"]))
    if not row:
        return jsonify({"error": "Alert not found."}), 404
    if row["status"] == "new":
        db.execute("UPDATE alerts SET status = 'acknowledged' WHERE id = ?", (alert_id,))
        gamification.award(g.user["id"], "reviewed_alert")
    return jsonify({"ok": True})


@user_bp.route("/prefs", methods=["PUT"])
@require_auth()
def prefs():
    from engine import crypto
    v = Validator(request.get_json(silent=True))
    v.boolean("email", default=True).boolean("sms", default=True)
    v.boolean("push", default=False)
    v.string("language", default="en", choices={"en", "ne"})
    v.string("trusted_contact", max_len=254)
    data = v.done()
    prefs = {c: data[c] for c in ("email", "sms", "push")}
    lang = data["language"] or "en"
    db.execute("UPDATE users SET prefs = ?, language = ? WHERE id = ?",
               (json.dumps(prefs), lang, g.user["id"]))
    if "trusted_contact" in data:
        tc = (data.get("trusted_contact") or "").strip()
        db.execute("UPDATE users SET trusted_contact_enc = ? WHERE id = ?",
                   (crypto.encrypt(tc) if tc else None, g.user["id"]))
    db.log_activity(g.user["id"], "prefs_updated", prefs)
    return jsonify({"ok": True, "prefs": prefs, "language": lang})


@user_bp.route("/safezones", methods=["PUT"])
@require_auth()
def safezones():
    """User-managed geo-fence: up to 5 named zones, fed into the pre-OTP check."""
    zones = (request.get_json(silent=True) or {}).get("zones", [])
    if not isinstance(zones, list) or len(zones) > 5:
        return jsonify({"error": "Provide up to 5 safe zones."}), 400
    clean = []
    for z in zones:
        try:
            lat, lon = float(z["lat"]), float(z["lon"])
        except (KeyError, TypeError, ValueError):
            return jsonify({"error": "Each zone needs a name, lat and lon."}), 400
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return jsonify({"error": "Coordinates out of range."}), 400
        clean.append({"name": str(z.get("name", "Zone"))[:60], "lat": lat, "lon": lon})
    db.execute("UPDATE users SET safe_zones = ? WHERE id = ?",
               (json.dumps(clean), g.user["id"]))
    db.log_activity(g.user["id"], "safezones_updated", {"count": len(clean)})
    return jsonify({"ok": True, "zones": clean})


@user_bp.route("/sessions")
@require_auth()
def sessions():
    token = request.headers.get("Authorization", "")[len("Bearer "):]
    return jsonify(auth.list_sessions(g.user["id"], current_token=token))


@user_bp.route("/sessions/<session_id>/revoke", methods=["POST"])
@require_auth()
def revoke_session(session_id: str):
    if not auth.revoke_session(g.user["id"], session_id):
        return jsonify({"error": "Session not found."}), 404
    return jsonify({"ok": True})


@user_bp.route("/freeze", methods=["POST"])
@require_auth()
def freeze():
    auth.set_frozen(g.user["id"], True, by="user")
    notifier.send(g.user, "Account frozen",
                  "Your account is now frozen: every transaction will be refused "
                  "until you unfreeze it (email OTP required).",
                  alert_type=None)
    return jsonify({"ok": True, "frozen": True})


@user_bp.route("/unfreeze/request", methods=["POST"])
@require_auth()
def unfreeze_request():
    if _limited("unfreeze", g.user["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    return jsonify({"ok": True,
                    "delivery": auth.issue_otp(g.user, purpose="unfreeze")})


@user_bp.route("/unfreeze/confirm", methods=["POST"])
@require_auth()
def unfreeze_confirm():
    if _limited("unfreeze", g.user["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    v = Validator(request.get_json(silent=True))
    v.string("code", required=True, max_len=12)
    data = v.done()
    if not auth.verify_otp(g.user["email"], data["code"], purpose="unfreeze"):
        return jsonify({"error": "Invalid or expired code."}), 401
    auth.set_frozen(g.user["id"], False, by="user")
    return jsonify({"ok": True, "frozen": False})


@user_bp.route("/transactions", methods=["GET", "POST"])
@require_auth()
def txns():
    if request.method == "GET":
        return jsonify(transactions.list_for_user(g.user["id"]))
    v = Validator(request.get_json(silent=True))
    # WHOLE RUPEES ONLY. `balance` is a SQLite REAL, and repeated subtraction of
    # fractional floats drifts (150000 − 0.1 × 1000 lands on 149899.99999999418).
    # Constraining amounts to integers makes the arithmetic exact — every value
    # stays a whole number well under 2^53, where IEEE-754 addition and
    # subtraction are exact — so the drift is unreachable rather than merely
    # unlikely. A production ledger would store integer paisa and use decimals;
    # that is recorded as a known simplification rather than pretended away.
    v.number("amount", required=True, integer=True, minimum=1, maximum=100_000_000)
    data = v.done()
    # Merchant and category are deliberately NOT accepted. Detecting a SIM swap
    # does not require knowing what a subscriber buys, so SIMShield does not ask
    # — the amount and the SIM-change history are the whole basis of the hold.
    # Older rows may still carry a merchant; nothing new writes one.
    result = transactions.assess(g.user, data["amount"])
    # Simulation only — no real funds move at any point.
    result["simulation_only"] = True
    return jsonify(result), (200 if result["accepted"] else 403)


@user_bp.route("/transactions/<int:txn_id>/release/request", methods=["POST"])
@require_auth()
def txn_release_request(txn_id: int):
    """Send the out-of-band email OTP that releases a held transaction."""
    if _limited("txn_release", g.user["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    txn = db.query_one("SELECT * FROM transactions WHERE id = ? AND user_id = ?",
                       (txn_id, g.user["id"]))
    if not txn or txn["status"] != "held":
        return jsonify({"error": "No held transaction with that ID."}), 404
    return jsonify({"ok": True, "delivery": auth.issue_otp(g.user, purpose="txnrelease")})


@user_bp.route("/transactions/<int:txn_id>/release/confirm", methods=["POST"])
@require_auth()
def txn_release_confirm(txn_id: int):
    if _limited("txn_release", g.user["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    v = Validator(request.get_json(silent=True))
    v.string("code", required=True, max_len=12)
    data = v.done()
    if not auth.verify_otp(g.user["email"], data["code"], purpose="txnrelease"):
        return jsonify({"error": "Invalid or expired code."}), 401
    try:
        result = transactions.release_held(g.user, txn_id)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    return jsonify(result)


@user_bp.route("/simulate-sim-swap", methods=["POST"])
@require_auth()
def simulate_sim_swap():
    """
    DEMO control: inject a synthetic SIM-swap event on the signed-in account so
    the full pipeline (sim_events row -> risk score jump -> alert -> outbox
    notification -> chatbot explanation) can be demonstrated live. In
    production this row would come from the operator's HLR/HSS feed instead.
    """
    u = g.user
    db.execute(
        "INSERT INTO sim_events (user_id, event_type, operator, imsi_hash, imei_hash, "
        "risk_score, details, occurred_at) VALUES (?,?,?,?,?,?,?,?)",
        (u["id"], "sim_swap", u.get("operator") or "NTC",
         privacy.hash_id("demo-imsi"), privacy.hash_id("demo-imei"), 92.0,
         "SYNTHETIC demo event injected by the account owner", db.now()))
    notifier.send(
        u, "⚠️ SIM change detected on your number",
        "Your mobile number was just moved to a different SIM card. If you did "
        "not request this, you may be the target of a SIM-swap attack: freeze "
        "your account now and call your operator. (Synthetic demo event.)",
        alert_type="sim_swap", severity="critical")
    db.log_activity(u["id"], "demo_sim_swap_injected", {})
    return jsonify({"ok": True, "risk": account_risk.compute(auth.get_user(u["id"]))})


@user_bp.route("/checklist", methods=["POST"])
@require_auth()
def checklist():
    item = str((request.get_json(silent=True) or {}).get("item", ""))[:60]
    if not item:
        return jsonify({"error": "item is required"}), 400
    done = db.query_one(
        "SELECT COUNT(*) AS n FROM activity_log WHERE user_id = ? AND action = ?",
        (g.user["id"], f"checklist_{item}"))
    if (done or {}).get("n", 0) > 0:
        return jsonify({"ok": True, "awarded": False})
    db.log_activity(g.user["id"], f"checklist_{item}", {})
    return jsonify({"ok": True, **gamification.award(g.user["id"], "checklist_item")})


@user_bp.route("/gamify/<event>", methods=["POST"])
@require_auth()
def gamify(event: str):
    if event not in ("study_completed", "quiz_perfect"):
        return jsonify({"error": "Unknown event."}), 400
    return jsonify(gamification.award(g.user["id"], event))


# --- Appeals: the subscriber's right of reply (improvement #3) -----------------
@user_bp.route("/appeals")
@require_auth()
def my_appeals():
    """
    A subscriber's own appeals, plus what they are currently able to appeal.

    Showing the appealable decision explicitly matters: a person who was just
    blocked should not have to work out that disputing it is even possible.
    """
    recent = db.query_one(
        "SELECT meta, created_at FROM activity_log WHERE user_id = ? "
        "AND action = 'pre_otp_check' ORDER BY id DESC LIMIT 1", (g.user["id"],))
    appealable = None
    if recent:
        meta = json.loads(recent["meta"] or "{}")
        if meta.get("decision") in appeals.APPEALABLE:
            appealable = {"decision": meta["decision"], "risk_score": meta.get("risk"),
                          "when": recent["created_at"]}
    return jsonify({"appeals": appeals.list_for_user(g.user["id"]),
                    "appealable": appealable,
                    "max_open": appeals.MAX_OPEN_PER_USER})


@user_bp.route("/appeals", methods=["POST"])
@require_auth()
def submit_appeal():
    if _limited("appeal_submit", g.user["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    v = Validator(request.get_json(silent=True))
    v.string("statement", required=True, max_len=4000)
    v.string("decision", choices=set(appeals.APPEALABLE))
    v.number("risk_score", minimum=0, maximum=100)
    clean = v.done()
    try:
        appeal = appeals.submit(g.user, clean["statement"],
                                decision=clean["decision"],
                                risk_score=clean["risk_score"])
    except appeals.AppealError as exc:
        return jsonify({"error": str(exc)}), 400
    return jsonify(appeal), 201


@user_bp.route("/appeals/<int:appeal_id>/withdraw", methods=["POST"])
@require_auth()
def withdraw_appeal(appeal_id: int):
    try:
        return jsonify(appeals.withdraw(appeal_id, g.user["id"]))
    except appeals.AppealError as exc:
        return jsonify({"error": str(exc)}), 400


# --- Phone-independent factors: passkeys and recovery codes (improvement #5) ---
@user_bp.route("/security/factors")
@require_auth()
def security_factors():
    """What the subscriber has that would survive a SIM swap."""
    return jsonify(webauthn.posture(g.user["id"]))


@user_bp.route("/recovery-codes", methods=["POST"])
@require_auth()
def generate_recovery_codes():
    """
    Issue a fresh set of recovery codes, invalidating any previous set.

    This is the ONLY response that ever contains the codes in readable form.
    They are stored as PBKDF2 hashes, so neither the bank nor an attacker with
    the database can recover them afterwards.
    """
    codes = recovery_codes.generate_for_user(g.user["id"])
    notifier.send(g.user, "New recovery codes were generated",
                  "A new set of account recovery codes was created. Your previous "
                  "codes no longer work. If this was not you, contact the bank.",
                  alert_type=None)
    return jsonify({
        "codes": codes,
        "count": len(codes),
        "warning": "These are shown once. Save them somewhere that is not your "
                   "phone — they exist so you can still get in when your number "
                   "has been taken.",
    })


@user_bp.route("/passkeys/register/options", methods=["POST"])
@require_auth()
def passkey_register_options():
    if _limited("passkey", g.user["email"]):
        return jsonify({"error": _RATE_MSG}), 429
    try:
        return jsonify(webauthn.registration_options(g.user))
    except webauthn.WebAuthnError as exc:
        return jsonify({"error": str(exc)}), 400


@user_bp.route("/passkeys/register", methods=["POST"])
@require_auth()
def passkey_register():
    v = Validator(request.get_json(silent=True))
    v.string("handle", required=True, max_len=64)
    v.string("label", max_len=60)
    clean = v.done()
    credential = (request.get_json(silent=True) or {}).get("credential")
    if not isinstance(credential, dict):
        return jsonify({"error": "A credential object is required."}), 400
    try:
        result = webauthn.register(g.user, clean["handle"], credential,
                                   label=clean["label"])
    except webauthn.WebAuthnError as exc:
        return jsonify({"error": str(exc)}), 400
    notifier.send(g.user, "A passkey was added to your account",
                  "A new passkey can now sign in to your account. If this was "
                  "not you, remove it immediately and contact the bank.",
                  alert_type=None)
    return jsonify(result), 201


@user_bp.route("/passkeys/<int:cred_id>", methods=["DELETE"])
@require_auth()
def passkey_delete(cred_id: int):
    if not webauthn.delete_credential(g.user["id"], cred_id):
        return jsonify({"error": "Passkey not found."}), 404
    return jsonify({"ok": True, "posture": webauthn.posture(g.user["id"])})

"""
SIMShield - Flask API + static frontend host.

Detection
    GET  /                      -> awareness landing page
    GET  /dashboard             -> scenario dashboard
    GET  /study                 -> user-study flow
    GET  /metrics               -> evaluation dashboard
    GET  /api/health            -> service + model status
    GET  /api/config            -> safe slice of the detection config
    GET  /api/users             -> synthetic demo profiles (masked)
    GET  /api/users/<id>        -> one profile (masked)
    GET  /api/scenarios         -> built-in demo scenarios
    POST /api/score             -> score a login -> risk + decision + reasons + alert
    GET  /api/education         -> awareness content

Privacy / ethics / accountability
    GET  /api/ethics            -> ethics & scope statement
    GET  /api/audit/verify      -> verify the tamper-evident audit chain
    POST /api/retention/enforce -> purge data past its retention window

User study & evaluation (mixed-methods)
    GET  /api/study/instrument  -> consent text, quiz, SUS items
    POST /api/study/submit      -> store one consented submission
    GET  /api/study/aggregate   -> aggregated study results
    GET  /api/study/export.csv  -> flat CSV of submissions
    GET  /api/evaluation        -> latest evaluation report (detection + study)

Defensive, demo-only prototype. All data is synthetic; processing is local-only.
"""
import json
import os

from flask import (Flask, Response, g, jsonify, redirect, request,
                   send_from_directory)

from engine import (anomaly, awareness, compliance, db, ml_model, operator,
                    playbook, privacy, profiles, security, settings, study)
from engine.config_loader import backend_path, load_compliance, load_config
from engine.detector import score_login
from engine.validation import Validator
from routes import ALL_BLUEPRINTS
from routes.common import (audit_access, owns_profile_or_admin, require_auth,
                           require_demo_mode)

FRONTEND_DIR = os.path.join(os.path.dirname(backend_path()), "frontend")
USERS_DIR = backend_path("data", "users")

# Refuse to start a production instance with any demo convenience enabled.
if settings.is_production():
    settings.assert_safe_for_production()

app = Flask(__name__, static_folder=FRONTEND_DIR, static_url_path="")
app.secret_key = settings.flask_secret_key()
# CORS is an explicit allowlist inside security.init_app — the previous
# `CORS(app)` allowed every origin (finding F2).
security.init_app(app)
db.init_db()
for bp in ALL_BLUEPRINTS:
    app.register_blueprint(bp)


# --- helpers ----------------------------------------------------------------
# Profile loading lives in engine.profiles so the API, the scenarios and the
# auth pre-OTP check all resolve relative ages ("SIM activated 1 day ago") the
# same way — see that module for why the fixtures are time-relative.
load_profile = profiles.load
list_profiles = profiles.list_all


def public_profile(p: dict) -> dict:
    """Profile view safe to display - contact is masked, IMEIs are not exposed."""
    return {
        "user_id": p["user_id"],
        "display_name": p.get("display_name"),
        "operator": p.get("operator"),
        "sim_activation_date": p.get("sim_activation_date"),
        "account_created": p.get("account_created"),
        "safe_zones": p.get("safe_zones", []),
        "registered_devices": len(p.get("known_imeis", [])),
        "num_sim_changes_last_30d": p.get("num_sim_changes_last_30d", 0),
        "last_login": p.get("last_login"),
        "contact": privacy.redact_contact(p.get("contact", {})),
    }


# --- static pages -----------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")


@app.route("/dashboard")
def dashboard():
    """Subscriber's main dashboard (the detection demo now lives at /detection)."""
    return send_from_directory(FRONTEND_DIR, "dashboard.html")


@app.route("/detection")
def detection_page():
    return send_from_directory(FRONTEND_DIR, "detection.html")


@app.route("/money")
def money_page():
    return send_from_directory(FRONTEND_DIR, "money.html")


@app.route("/defence")
def defence_page():
    return send_from_directory(FRONTEND_DIR, "defence.html")


@app.route("/awareness")
def awareness_page():
    return send_from_directory(FRONTEND_DIR, "awareness.html")


@app.route("/assistant")
def assistant_page():
    return send_from_directory(FRONTEND_DIR, "assistant.html")


@app.route("/study")
def study_page():
    return send_from_directory(FRONTEND_DIR, "study.html")


@app.route("/metrics")
def metrics_page():
    return send_from_directory(FRONTEND_DIR, "metrics.html")


@app.route("/login")
def login_page():
    return send_from_directory(FRONTEND_DIR, "login.html")


@app.route("/register")
def register_page():
    return send_from_directory(FRONTEND_DIR, "register.html")


@app.route("/account")
def account_page():
    """Legacy single-page account view. Its features now live across
    /dashboard, /money and /defence. Kept as a redirect so old links, the PWA
    manifest shortcut and any installed home-screen icon still work."""
    return redirect("/dashboard", code=302)


@app.route("/admin")
def admin_page():
    return send_from_directory(FRONTEND_DIR, "admin.html")


@app.route("/api/playbook")
def playbook_api():
    lang = request.args.get("lang", "en")
    return jsonify(playbook.get_playbook(lang))


# --- Mobile-operator integration (SIMULATED) ---------------------------------
# These mirror the GSMA Open Gateway / CAMARA endpoints that operators already
# sell to banks. They are the ONLY legitimate way to learn a SIM's status or
# whereabouts — see engine/operator.py for what a real integration requires.
#
# AUTHORISATION (finding F5): SIM location and swap status are personal data
# about a subscriber. These endpoints were unauthenticated, so anyone who could
# guess a profile id could learn where a SIM was and whether it had just been
# swapped — precisely the reconnaissance a SIM-swap attacker wants. Access now
# requires a session, is restricted to the owning subscriber or an admin, and
# every read is written to the activity log.
@app.route("/api/operator/sim-location")
@require_auth()
@audit_access("operator.sim_location")
def operator_sim_location():
    """CAMARA `location-retrieval` equivalent: where the network says the SIM is."""
    profile_id = request.args.get("user_id", "")
    if not owns_profile_or_admin(profile_id):
        return jsonify({"error": "You may only query your own SIM."}), 403
    profile = load_profile(profile_id)
    if profile is None:
        return jsonify({"error": "Unknown subscriber profile."}), 404
    fallback = None
    if request.args.get("lat") is not None and request.args.get("lon") is not None:
        v = Validator({"lat": request.args.get("lat"),
                       "lon": request.args.get("lon")})
        v.number("lat", required=True, minimum=-90, maximum=90)
        v.number("lon", required=True, minimum=-180, maximum=180)
        clean = v.done()
        fallback = {"lat": clean["lat"], "lon": clean["lon"]}
    loc = operator.get_sim_location(profile, fallback=fallback)
    # The adapter coarsens to an area at the boundary, so there is no
    # coordinate here to leak — see engine/operator_adapter.py. A degraded
    # lookup is reported as a 200 with an explicit status rather than a 404,
    # because "the operator is down" and "no such SIM" are different answers
    # and the client must be able to tell them apart.
    return jsonify({"operator": profile.get("operator"),
                    "status": loc["status"], "usable": loc["usable"],
                    "cell_id": loc["cell_id"], "area": loc["area"],
                    "country": loc["country"],
                    "distance_band": loc["distance_band"],
                    "origin": loc["origin"], "source": loc["source"],
                    "degraded_reason": loc["degraded_reason"],
                    "retrieved_at": loc["retrieved_at"],
                    "explain": loc["explain"], "simulated": loc["simulated"]})


@app.route("/api/operator/sim-swap-check")
@require_auth()
@audit_access("operator.sim_swap_check")
def operator_sim_swap_check():
    """CAMARA `sim-swap/check` equivalent: did this SIM change recently?"""
    profile_id = request.args.get("user_id", "")
    if not owns_profile_or_admin(profile_id):
        return jsonify({"error": "You may only query your own SIM."}), 403
    profile = load_profile(profile_id)
    if profile is None:
        return jsonify({"error": "Unknown subscriber profile."}), 404
    v = Validator({"max_age_days": request.args.get("max_age_days", 7)})
    v.number("max_age_days", integer=True, minimum=1, maximum=365, default=7)
    return jsonify(operator.sim_swap_check(
        profile, max_age_days=v.done()["max_age_days"]))


@app.route("/api/config/public")
def public_config():
    """
    The handful of tuning values the UI needs to describe its own behaviour.

    The Exposure page says "for N days after a SIM change, payments are held".
    Reading N from here rather than hardcoding it in the copy means the sentence
    cannot drift out of step with `config.yaml` — a small thing, but wording
    that contradicts the running system is exactly the kind of over-claim the
    remediation set out to remove.

    Deliberately a tiny allowlist: thresholds an attacker could use to tune an
    attack under the detection line are NOT exposed.
    """
    txn = load_config()["transactions"]
    return jsonify({
        "sim_change_lookback_days": txn["sim_change_lookback_days"],
        "hold_threshold_amount": txn["hold_threshold_amount"],
        "currency": "NPR",
        "simulated": True,
    })


@app.route("/api/operator/health")
def operator_health():
    """
    Which operator adapter is in use, and its degradation posture.

    Unauthenticated on purpose: it discloses no subscriber data, only this
    deployment's own configuration — and the honest answer ("simulated, not a
    real integration") is one a reader of the dissertation should be able to
    check without an account.
    """
    return jsonify(operator.health())


# --- PWA assets -------------------------------------------------------------
# The static handler already serves everything in frontend/ at the site root,
# but two files need explicit handling: .webmanifest has no registered MIME type
# on most systems, and the service worker must never be served from a stale
# HTTP cache or clients would be pinned to an old version of the app shell.
@app.route("/manifest.webmanifest")
def manifest():
    resp = send_from_directory(FRONTEND_DIR, "manifest.webmanifest")
    resp.headers["Content-Type"] = "application/manifest+json"
    return resp


@app.route("/sw.js")
def service_worker():
    resp = send_from_directory(FRONTEND_DIR, "sw.js")
    resp.headers["Content-Type"] = "application/javascript"
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    # allow the worker to control the whole origin, not just /sw.js
    resp.headers["Service-Worker-Allowed"] = "/"
    return resp


@app.route("/offline.html")
def offline_page():
    return send_from_directory(FRONTEND_DIR, "offline.html")


# --- detection API ----------------------------------------------------------
@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "app": "SIMShield",
                    "environment": settings.environment(),
                    "ml_model_loaded": ml_model.is_available(),
                    "anomaly_model_loaded": anomaly.iso_available(),
                    "demo_endpoints": settings.demo_endpoints_enabled(),
                    "mode": "ml+rules" if ml_model.is_available() else "rules-only"})


@app.route("/api/config")
def get_config():
    cfg = load_config()
    return jsonify({"fusion": cfg["fusion"],
                    "rule_weights": cfg["rule_engine"]["weights"],
                    "decision_thresholds": cfg["decision_thresholds"],
                    "locale": cfg["locale"],
                    "ml_features": cfg["ml"]["features"]})


# The endpoints below serve CLEARLY-LABELLED SYNTHETIC demonstration data and
# perform unauthenticated work (scoring, audit writes, simulated alerts). They
# are disabled outside development/demo so a production instance exposes no
# unauthenticated compute (findings F22, and P0.3's demo-gating requirement).
@app.route("/api/users")
@require_demo_mode
def users():
    return jsonify({"synthetic": True, "profiles": list_profiles()})


@app.route("/api/users/<user_id>")
@require_demo_mode
def user(user_id):
    p = load_profile(user_id)
    if p is None:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"synthetic": True, **public_profile(p)})


@app.route("/api/scenarios")
@require_demo_mode
def scenarios():
    """Flat list of all 40 demo scenarios (10 per decision class)."""
    from scenarios import SCENARIOS
    return jsonify([{"name": s["name"], "user_id": s["profile"]["user_id"],
                     "expected_decision": s["expected_decision"],
                     "note": s.get("note", ""),
                     "attempt": s["attempt"]} for s in SCENARIOS])


@app.route("/api/scenarios/grouped")
@require_demo_mode
def scenarios_grouped():
    """The same scenarios grouped by expected decision, for the demo picker."""
    from scenarios import SCENARIO_GROUPS
    return jsonify([
        {"decision": grp["decision"], "label": grp["label"],
         "scenarios": [{"name": s["name"], "user_id": s["profile"]["user_id"],
                        "expected_decision": s["expected_decision"],
                        "note": s.get("note", ""), "attempt": s["attempt"]}
                       for s in grp["scenarios"]]}
        for grp in SCENARIO_GROUPS])


@app.route("/api/education")
def education():
    return jsonify(awareness.get_education())


@app.route("/api/score", methods=["POST"])
@require_demo_mode
def score():
    """
    Score a SYNTHETIC login against a SYNTHETIC profile. Demo-only: it performs
    unauthenticated work and writes audit records, so it is unavailable outside
    development/demo. Every field is validated — NaN/infinite coordinates and
    out-of-range values previously reached the scoring maths (finding F16).
    """
    v = Validator(request.get_json(silent=True))
    v.identifier("user_id", required=True, max_len=64)
    v.coordinates("current_location")
    v.string("imei", max_len=32)
    v.timestamp("timestamp")
    v.number("logins_last_24h", integer=True, minimum=0, maximum=10_000, default=0)
    v.number("failed_logins_last_24h", integer=True, minimum=0, maximum=10_000, default=0)
    for flag in ("imsi_change_flag", "iccid_change_flag",
                 "sim_type_change_flag", "ip_change_flag"):
        v.flag01(flag)
    v.number("otp_sim_gap_minutes", minimum=0, maximum=525_600, default=None)
    data = v.done()

    profile = load_profile(data["user_id"])
    if profile is None:
        return jsonify({"error": "User not found"}), 404

    attempt = {k: data[k] for k in (
        "current_location", "imei", "timestamp", "logins_last_24h",
        "failed_logins_last_24h", "imsi_change_flag", "iccid_change_flag",
        "sim_type_change_flag", "ip_change_flag", "otp_sim_gap_minutes")}

    result = score_login(attempt, profile)
    result["reasons"] = awareness.explain_decision(result)
    result["alert"] = awareness.maybe_send_alert(data["user_id"], result, profile)
    result["user"] = {"user_id": data["user_id"],
                      "display_name": profile.get("display_name")}
    result["synthetic"] = True
    compliance.record_decision(data["user_id"], attempt, result)
    return jsonify(result)


# --- privacy / ethics / accountability --------------------------------------
@app.route("/api/ethics")
def ethics():
    return jsonify(compliance.ethics_notice())


@app.route("/api/audit/verify")
def audit_verify():
    return jsonify(compliance.verify_audit_chain())


@app.route("/api/audit/checkpoint", methods=["POST"])
@require_auth(role="admin")
def audit_checkpoint():
    """Sign the current chain head so later truncation is detectable."""
    return jsonify(compliance.checkpoint_audit(reason="admin"))


@app.route("/api/retention/enforce", methods=["POST"])
@require_auth(role="admin")
@audit_access("retention.enforce")
def retention_enforce():
    """
    DESTRUCTIVE — purges data past its retention window.

    This was previously an unauthenticated POST (finding F4): any caller could
    erase the audit log, destroying the accountability the project claims. It is
    now admin-only, CSRF-protected, and the invocation is itself audited.
    """
    return jsonify(compliance.enforce_retention())


# --- user study & evaluation ------------------------------------------------
@app.route("/api/study/instrument")
def study_instrument():
    """Public: the consent text, participant information sheet and questions."""
    return jsonify(study.instrument())


@app.route("/api/study/submit", methods=["POST"])
def study_submit():
    result = study.submit(request.get_json(silent=True) or {},
                          client_ip=request.remote_addr)
    return jsonify(result), (200 if result.get("ok") else
                             429 if result.get("rate_limited") else 400)


# Research outputs are restricted (finding F6). Aggregates and especially the
# raw export contain participants' free-text answers, which ethics approval
# requires be protected. Both are researcher/admin-only and every export is
# recorded so any disclosure is attributable.
@app.route("/api/study/aggregate")
@require_auth(roles=("admin", "researcher"))
@audit_access("study.aggregate")
def study_aggregate():
    return jsonify(study.aggregate())


@app.route("/api/study/export.csv")
@require_auth(roles=("admin", "researcher"))
@audit_access("study.export_csv")
def study_export():
    return Response(study.export_csv(include_feedback=False),
                    mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=simshield_study.csv"})


@app.route("/api/study/export-feedback.csv")
@require_auth(roles=("admin", "researcher"))
@audit_access("study.export_feedback")
def study_export_feedback():
    """
    Qualitative free-text, exported SEPARATELY from the quantitative measures so
    the two are not casually joined (finding F21). Participant ids are replaced
    with per-export pseudonyms.
    """
    return Response(study.export_feedback_csv(), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=simshield_feedback.csv"})


@app.route("/api/evaluation")
def evaluation():
    """
    The latest evaluation report, or an explicit "not generated yet" answer.

    This used to 404 on a fresh clone, because the report is generated output
    and is deliberately git-ignored. The /metrics page then had nothing to
    render and simply looked broken, with the reason visible only in the
    browser console. A missing report is an ordinary first-run state, not an
    error — so it is reported as one, with the command that fixes it.
    """
    path = backend_path("data", "evaluation_report.json")
    if not os.path.exists(path):
        return jsonify({
            "available": False,
            "message": "No evaluation report has been generated yet.",
            "how_to_fix": "Run `python evaluate.py` in the backend folder, "
                          "then reload this page.",
        })
    with open(path, "r", encoding="utf-8") as f:
        report = json.load(f)
    report["available"] = True
    return jsonify(report)


def run_config() -> dict:
    """
    The exact keyword arguments used to start the development server.

    Extracted into a function so a TEST can assert on what the real entry point
    would do, rather than merely re-checking `settings.debug_enabled()` in
    isolation. Debug is environment-gated and is False in every environment
    except development-with-explicit-opt-in; the Werkzeug debugger is a remote
    code execution primitive, so it must never be on by default (finding F1).
    """
    return {
        "debug": settings.debug_enabled(),
        "host": os.environ.get("SIMSHIELD_HOST", "127.0.0.1"),
        "port": int(os.environ.get("SIMSHIELD_PORT", "5000")),
        "use_reloader": settings.debug_enabled(),
    }


def main() -> None:
    # Enforce retention on startup (privacy by default).
    if load_compliance()["retention"]["purge_on_startup"]:
        try:
            compliance.enforce_retention()
        except Exception as e:
            print(f"[retention] skipped: {e}")

    cfg = run_config()
    print("=" * 62)
    print("  SIMShield - SIM-Swap Detection & User-Awareness System")
    print("  Defensive prototype. Synthetic data only. Local-only processing.")
    print(f"  environment={settings.environment()}  debug={cfg['debug']}")
    print(f"  Open http://{cfg['host']}:{cfg['port']}")
    print("=" * 62)
    app.run(**cfg)


if __name__ == "__main__":
    main()

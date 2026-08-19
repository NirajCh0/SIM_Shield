"""'Spot the scam' trainer API. Works anonymously; signed-in users earn points
(capped so the trainer can't be farmed)."""
from flask import Blueprint, jsonify, request

from engine import db, gamification, scamsim
from routes.common import current_user

awareness_bp = Blueprint("awareness_api", __name__, url_prefix="/api/scamsim")

_SCAM_POINT_CAP = 10   # max scam_spotted awards per user


@awareness_bp.route("/quiz")
def quiz():
    return jsonify(scamsim.quiz(n=int(request.args.get("n", 5))))


@awareness_bp.route("/check", methods=["POST"])
def check():
    data = request.get_json(silent=True) or {}
    result = scamsim.check(str(data.get("id", "")), bool(data.get("guess_scam")))
    if result is None:
        return jsonify({"error": "Unknown item."}), 404
    user = current_user()
    if user and result["correct"]:
        n = db.query_one(
            "SELECT COUNT(*) AS n FROM activity_log WHERE user_id = ? "
            "AND action = 'gamify_scam_spotted'", (user["id"],))
        if (n or {}).get("n", 0) < _SCAM_POINT_CAP:
            award = gamification.award(user["id"], "scam_spotted")
            result["points"] = award.get("points", 0)
    return jsonify(result)

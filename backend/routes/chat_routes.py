"""Chatbot API — works anonymously; richer (alert explanation, escalation) when
signed in. Awards small gamification points for engaging with the assistant."""
from flask import Blueprint, jsonify, request

from engine import chatbot, db, gamification
from routes.common import current_user, require_auth

chat_bp = Blueprint("chat", __name__, url_prefix="/api/chat")

_CHAT_POINT_CAP = 5   # award chatbot points at most this many times per user


@chat_bp.route("", methods=["POST"])
def chat():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", ""))[:500]
    if not message.strip():
        return jsonify({"error": "message is required"}), 400
    user = current_user()
    lang = data.get("lang") or (user.get("language") if user else "en") or "en"
    result = chatbot.reply(message, user=user, lang=lang)
    if user:
        n = db.query_one(
            "SELECT COUNT(*) AS n FROM activity_log WHERE user_id = ? "
            "AND action = 'gamify_chatbot_question'", (user["id"],))
        if (n or {}).get("n", 0) < _CHAT_POINT_CAP:
            gamification.award(user["id"], "chatbot_question")
    return jsonify(result)


@chat_bp.route("/history")
@require_auth()
def chat_history():
    from flask import g
    return jsonify(chatbot.history(g.user["id"]))

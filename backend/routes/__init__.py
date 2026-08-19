"""Flask blueprints for SIMShield's account/banking API."""
from .admin_routes import admin_bp
from .auth_routes import auth_bp
from .awareness_routes import awareness_bp
from .chat_routes import chat_bp
from .user_routes import user_bp

ALL_BLUEPRINTS = [auth_bp, user_bp, chat_bp, admin_bp, awareness_bp]

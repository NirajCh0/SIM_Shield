"""
Request-scoped authentication, authorisation and CSRF helpers.

Session transport (finding F12, staged)
---------------------------------------
Sessions are now issued as an **HttpOnly, SameSite=Lax cookie** (Secure when TLS
is configured), which is unreachable from JavaScript and therefore not
exfiltratable by XSS. The legacy `Authorization: Bearer` header is still
accepted so the existing frontend and the test suite keep working during the
staged migration — but it is accepted *only* outside production, so a real
deployment gets cookies alone. The migration plan is recorded in
SECURITY_REMEDIATION.md §6.

CSRF (finding F13)
------------------
Because the cookie is SameSite=Lax, cross-site POSTs do not carry it. For
defence in depth every state-changing request must additionally present the
double-submit token from `X-CSRF-Token`, which the browser can only read from a
non-HttpOnly companion cookie set at login.
"""
import hmac
from functools import wraps

from flask import g, jsonify, make_response, request

from engine import auth, db, settings

SESSION_COOKIE = "simshield_session"
CSRF_COOKIE = "simshield_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


# --- session transport -------------------------------------------------------
def set_session_cookies(resp, token: str, csrf: str, max_age_seconds: int):
    """Attach the session + CSRF cookies to a login response."""
    secure = settings.https_enabled()
    resp.set_cookie(SESSION_COOKIE, token, max_age=max_age_seconds,
                    httponly=True, secure=secure, samesite="Lax", path="/")
    # Readable by JS on purpose: the page must echo it back in X-CSRF-Token.
    resp.set_cookie(CSRF_COOKIE, csrf, max_age=max_age_seconds,
                    httponly=False, secure=secure, samesite="Lax", path="/")
    return resp


def clear_session_cookies(resp):
    resp.delete_cookie(SESSION_COOKIE, path="/")
    resp.delete_cookie(CSRF_COOKIE, path="/")
    return resp


def session_token() -> str | None:
    """Cookie first; bearer header only outside production (staged migration)."""
    tok = request.cookies.get(SESSION_COOKIE)
    if tok:
        return tok
    if not settings.is_production():
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            return header[len("Bearer "):].strip() or None
    return None


def current_user() -> dict | None:
    return auth.get_session_user(session_token())


# --- CSRF --------------------------------------------------------------------
def csrf_ok() -> bool:
    """Double-submit check for state-changing requests."""
    if request.method in SAFE_METHODS:
        return True
    # Requests authenticated by the legacy bearer header cannot be forged by a
    # cross-site form (a browser will not attach it automatically), so CSRF does
    # not apply to them. Cookie-authenticated requests must present the token.
    if not request.cookies.get(SESSION_COOKIE):
        return True
    sent = request.headers.get(CSRF_HEADER, "")
    expected = request.cookies.get(CSRF_COOKIE, "")
    return bool(sent and expected and hmac.compare_digest(sent, expected))


# --- decorators --------------------------------------------------------------
def require_auth(role: str | None = None, roles: tuple | None = None):
    """
    Reject the request unless a valid session exists (and, when given, the user
    holds one of the required roles). Enforces CSRF on state-changing methods.
    """
    allowed = tuple(roles) if roles else ((role,) if role else None)

    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user()
            if user is None:
                return jsonify({"error": "Sign in required."}), 401
            if not csrf_ok():
                return jsonify({"error": "CSRF token missing or invalid."}), 403
            if allowed and user["role"] not in allowed:
                return jsonify({"error": "Insufficient permissions."}), 403
            g.user = user
            return fn(*args, **kwargs)
        return wrapper
    return deco


def require_demo_mode(fn):
    """
    Gate an endpoint that serves clearly-labelled synthetic examples and does
    unauthenticated work. Unavailable in production (finding F22).
    """
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not settings.demo_endpoints_enabled():
            return jsonify({
                "error": "This synthetic demonstration endpoint is disabled in "
                         "this environment.",
                "environment": settings.environment(),
            }), 404
        return fn(*args, **kwargs)
    return wrapper


def audit_access(resource: str):
    """
    Record that an authenticated principal read a sensitive resource.
    Applied to the operator APIs and the study export so every disclosure of
    location, SIM status or research data leaves a trace (finding F5/F6).
    """
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = getattr(g, "user", None)
            db.log_activity(
                user["id"] if user else None,
                "sensitive_access",
                {"resource": resource,
                 "target": request.args.get("user_id") or request.view_args or {},
                 "role": user["role"] if user else "anonymous",
                 "path": request.path},
            )
            return fn(*args, **kwargs)
        return wrapper
    return deco


def owns_profile_or_admin(profile_id: str) -> bool:
    """
    True when the caller is an admin, or the signed-in subscriber whose account
    is linked to this synthetic telecom profile. Prevents one subscriber from
    reading another's SIM location.
    """
    user = getattr(g, "user", None)
    if not user:
        return False
    if user["role"] == "admin":
        return True
    return bool(profile_id) and user.get("profile_id") == profile_id

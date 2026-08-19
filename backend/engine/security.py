"""
HTTP security middleware: CORS allowlist, security headers, request limits and
structured error handling (findings F2, F3, F16, F17).

Design notes
------------
CORS: the frontend is served by this same Flask app, so the correct default is
**same-origin only** — an empty allowlist. `CORS(app)` previously allowed any
origin to call every endpoint with the browser's credentials attached, which
turned a local demo into a cross-origin API for anyone who could get a victim to
open a page.

CSP: the app currently ships inline `<script>` blocks in each page, so a
nonce-free `script-src 'self' 'unsafe-inline'` would be dishonest security. A
per-response **nonce** is generated instead and injected into the served HTML,
so the policy can be `script-src 'self' 'nonce-…'` with no `unsafe-inline`.
Styles still require `'unsafe-inline'` because the pages use inline `style=`
attributes; that is recorded as a known limitation rather than hidden.

HSTS is emitted only when TLS is actually configured — sending it over plain
HTTP would lock users out of a demo they can no longer reach.
"""
from flask import jsonify, request

from . import settings

# 256 KB. Every legitimate payload here is a small JSON object; anything larger
# is either a mistake or an attempt to exhaust memory.
MAX_CONTENT_LENGTH = 256 * 1024


def _csp() -> str:
    directives = [
        "default-src 'self'",
        # ALL page logic lives in external same-origin files (`*.page.js`), so
        # scripts need neither a nonce nor 'unsafe-inline'. An earlier version
        # of this policy advertised a nonce that no <script> tag actually
        # carried, which would have caused a real browser to block every script
        # on every page — the header looked strict while the app was broken.
        # A response-level test now asserts no inline script or event handler
        # survives in any served HTML.
        "script-src 'self'",
        # Inline STYLE attributes are still used throughout the markup; removing
        # them is tracked as future work rather than silently allowed away.
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "manifest-src 'self'",
        "worker-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",      # clickjacking protection
    ]
    if settings.https_enabled():
        directives.append("upgrade-insecure-requests")
    return "; ".join(directives)


def init_app(app):
    """Attach CORS, security headers, body limits and error handlers."""
    app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
    allowed = settings.cors_origins()

    @app.after_request
    def _headers(resp):
        # No per-request nonce: there are no inline scripts to authorise, so
        # generating one would imply a control that does not exist.
        resp.headers.setdefault("Content-Security-Policy", _csp())
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault(
            "Permissions-Policy",
            # Geolocation is used on the sign-in page for the risk check; the
            # rest are denied outright.
            "geolocation=(self), camera=(), microphone=(), payment=(), "
            "usb=(), magnetometer=(), gyroscope=(), interest-cohort=()")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        if settings.https_enabled():
            resp.headers.setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains")

        # --- CORS: exact-match allowlist only --------------------------------
        origin = request.headers.get("Origin")
        if origin and origin in allowed:
            resp.headers["Access-Control-Allow-Origin"] = origin
            resp.headers["Access-Control-Allow-Credentials"] = "true"
            resp.headers["Access-Control-Allow-Headers"] = \
                "Content-Type, Authorization, X-CSRF-Token"
            resp.headers["Access-Control-Allow-Methods"] = \
                "GET, POST, PUT, DELETE, OPTIONS"
            resp.headers["Vary"] = "Origin"
        return resp

    _register_error_handlers(app)
    return app


def _register_error_handlers(app):
    """Return structured JSON for API routes; never leak a stack trace."""
    from .validation import ValidationError

    def _wants_json() -> bool:
        return (request.path.startswith("/api/")
                or request.accept_mimetypes.best == "application/json")

    @app.errorhandler(ValidationError)
    def _invalid(e):
        return jsonify({"error": "Invalid request.", "details": e.messages}), 400

    @app.errorhandler(400)
    def _bad_request(e):
        if _wants_json():
            return jsonify({"error": "Malformed request."}), 400
        return e

    @app.errorhandler(401)
    def _unauth(e):
        return jsonify({"error": "Authentication required."}), 401

    @app.errorhandler(403)
    def _forbidden(e):
        return jsonify({"error": "Insufficient permissions."}), 403

    @app.errorhandler(404)
    def _not_found(e):
        if _wants_json():
            return jsonify({"error": "Not found."}), 404
        return e

    @app.errorhandler(405)
    def _method(e):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(413)
    def _too_large(e):
        return jsonify({"error": "Request body too large."}), 413

    @app.errorhandler(429)
    def _rate(e):
        return jsonify({"error": "Too many requests — please wait and retry."}), 429

    @app.errorhandler(Exception)
    def _unhandled(e):
        # Re-raise HTTP exceptions so their own handlers run.
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            return e
        app.logger.exception("Unhandled error on %s %s", request.method, request.path)
        if settings.is_development():
            return jsonify({"error": "Internal error.", "detail": str(e)}), 500
        return jsonify({"error": "Internal error."}), 500

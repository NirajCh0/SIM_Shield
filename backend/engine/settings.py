"""
Environment and runtime-safety configuration.

SIMShield runs in exactly one of three environments:

    development   local coding. Debug still OFF. Demo endpoints available.
                  Missing secrets are auto-generated so `python app.py` works
                  out of the box — acceptable ONLY because nothing here is real.
    demo          a demonstration that may be shown to other people. Demo
                  endpoints available; OTP reveal is possible but must be
                  switched on deliberately.
    production    refuses to start unless every unsafe convenience is off and
                  every secret is supplied from the environment.

The production gate (`assert_safe_for_production`) exists because the dangerous
settings in this project are all *conveniences* — revealed OTPs, seeded demo
credentials, an auto-generated encryption key, wildcard CORS. Any of them
reaching a real deployment would be worse than having no security at all, since
the UI would still claim to be protecting the user. Failing to boot is the
correct behaviour.

Nothing here weakens the defensive posture: there is no setting that enables
offensive capability, because the project has none.
"""
import base64
import os
import secrets

# --- .env loading -------------------------------------------------------------
# The README's first setup step is `copy .env.example .env`, and .env.example
# documents every setting — but for a long time NOTHING READ THAT FILE. Values a
# user carefully set were silently ignored, with no error to explain why. That is
# worse than having no .env support at all, because the documentation promised a
# mechanism that did not exist.
#
# `override=False` is deliberate: a real environment variable always beats the
# file, so a deployment that exports SIMSHIELD_ENV=production cannot be quietly
# downgraded by a stale .env left in the working tree.
def _load_dotenv() -> None:
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), os.pardir, ".env")
    path = os.path.normpath(path)
    if not os.path.exists(path):
        return
    try:
        from dotenv import load_dotenv
    except ImportError:
        # Fall back to a minimal parser rather than failing to start. This keeps
        # an existing checkout working if the dependency has not been installed.
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key, value = key.strip(), value.strip().strip('"').strip("'")
                    if key and key not in os.environ:
                        os.environ[key] = value
        except OSError:
            pass
        return
    load_dotenv(path, override=False)


_load_dotenv()

DEVELOPMENT = "development"
DEMO = "demo"
PRODUCTION = "production"
VALID_ENVS = (DEVELOPMENT, DEMO, PRODUCTION)


class InsecureConfiguration(RuntimeError):
    """Raised when production is asked to start with an unsafe setting."""


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _flag(name: str, default: bool = False) -> bool:
    raw = _env(name)
    if not raw:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


def environment() -> str:
    env = _env("SIMSHIELD_ENV", DEVELOPMENT).lower()
    return env if env in VALID_ENVS else DEVELOPMENT


def is_production() -> bool:
    return environment() == PRODUCTION


def is_demo() -> bool:
    return environment() == DEMO


def is_development() -> bool:
    return environment() == DEVELOPMENT


# --- feature gates -----------------------------------------------------------
def demo_endpoints_enabled() -> bool:
    """
    /api/score, /api/scenarios and the synthetic-profile endpoints. These serve
    clearly-labelled synthetic examples and perform unauthenticated work, so
    they are unavailable in production.
    """
    if is_production():
        return False
    return _flag("SIMSHIELD_ENABLE_DEMO_ENDPOINTS", True)


def reveal_otp_enabled() -> bool:
    """
    Whether one-time codes may be echoed back in API responses. NEVER true in
    production — the production gate refuses to boot if it is set.
    """
    if is_production():
        return False
    return _flag("SIMSHIELD_DEMO_REVEAL_OTP", is_development())


def https_enabled() -> bool:
    return _flag("SIMSHIELD_HTTPS", False)


def debug_enabled() -> bool:
    """Debug is opt-in and never available outside development."""
    return is_development() and _flag("SIMSHIELD_DEBUG", False)


# --- CORS --------------------------------------------------------------------
def cors_origins() -> list[str]:
    """
    Exact-match origin allowlist. Empty list means same-origin only, which is
    the correct default because the frontend is served by this same app.
    """
    raw = _env("SIMSHIELD_CORS_ORIGINS")
    if not raw:
        return []
    return [o.strip() for o in raw.split(",") if o.strip()]


# --- secrets -----------------------------------------------------------------
# In development a missing secret is generated per-process so the app runs
# without setup. The values are deliberately NOT persisted: a restart rotates
# them, which is a visible reminder that they are not real secrets.
_ephemeral: dict[str, str] = {}


def _secret(name: str, generator) -> str:
    value = _env(name)
    if value:
        return value
    if is_production():
        raise InsecureConfiguration(
            f"{name} must be set from the environment in production. "
            "See .env.example.")
    if name not in _ephemeral:
        _ephemeral[name] = generator()
    return _ephemeral[name]


def aes_key_b64() -> str:
    """Base64 32-byte key for AES-256-GCM field encryption."""
    return _secret("SIMSHIELD_AES_KEY",
                   lambda: base64.b64encode(os.urandom(32)).decode("ascii"))


def pseudonym_secret() -> str:
    """High-entropy secret keying the HMAC used for pseudonymisation."""
    return _secret("SIMSHIELD_PSEUDONYM_SECRET",
                   lambda: secrets.token_urlsafe(48))


def flask_secret_key() -> str:
    return _secret("SIMSHIELD_SECRET_KEY", lambda: secrets.token_urlsafe(48))


def aes_key_is_ephemeral() -> bool:
    """True when the AES key was generated rather than supplied."""
    return not _env("SIMSHIELD_AES_KEY")


# --- the production safety gate ----------------------------------------------
def production_problems() -> list[str]:
    """
    Every reason production must not start. Returned as a list (rather than
    raising on the first) so an operator sees the whole picture at once.
    """
    problems: list[str] = []
    if not is_production():
        return problems

    if _flag("SIMSHIELD_DEMO_REVEAL_OTP"):
        problems.append(
            "SIMSHIELD_DEMO_REVEAL_OTP is enabled — one-time codes would be "
            "returned in API responses.")
    if _flag("SIMSHIELD_ENABLE_DEMO_ENDPOINTS"):
        problems.append(
            "SIMSHIELD_ENABLE_DEMO_ENDPOINTS is enabled — unauthenticated "
            "synthetic scoring endpoints would be exposed.")
    if _flag("SIMSHIELD_DEBUG"):
        problems.append("SIMSHIELD_DEBUG is enabled — the Werkzeug debugger "
                        "permits remote code execution.")
    if _flag("SIMSHIELD_ALLOW_DEMO_CREDENTIALS"):
        problems.append("SIMSHIELD_ALLOW_DEMO_CREDENTIALS is enabled — seeded "
                        "demo accounts with published passwords would exist.")

    for name in ("SIMSHIELD_AES_KEY", "SIMSHIELD_PSEUDONYM_SECRET",
                 "SIMSHIELD_SECRET_KEY"):
        if not _env(name):
            problems.append(f"{name} is not set — a generated per-process "
                            "secret is not acceptable in production.")

    key = _env("SIMSHIELD_AES_KEY")
    if key:
        try:
            if len(base64.b64decode(key)) != 32:
                problems.append("SIMSHIELD_AES_KEY must decode to exactly 32 bytes.")
        except Exception:
            problems.append("SIMSHIELD_AES_KEY is not valid base64.")

    ps = _env("SIMSHIELD_PSEUDONYM_SECRET")
    if ps and len(ps) < 32:
        problems.append("SIMSHIELD_PSEUDONYM_SECRET is too short "
                        "(need >= 32 characters of high entropy).")

    for origin in cors_origins():
        if origin == "*" or origin.startswith("*"):
            problems.append(f"Wildcard CORS origin {origin!r} is not permitted.")
        elif not origin.startswith("https://"):
            problems.append(f"CORS origin {origin!r} must use https:// in production.")

    if not https_enabled():
        problems.append("SIMSHIELD_HTTPS is false — production must terminate "
                        "TLS so cookies can be Secure and HSTS can be sent.")

    # Fail closed if the crypto backend is unavailable rather than silently
    # writing plaintext PII (finding F10).
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: F401
    except Exception:
        problems.append("The `cryptography` package is unavailable — PII "
                        "encryption cannot be performed.")
    return problems


def assert_safe_for_production() -> None:
    problems = production_problems()
    if problems:
        raise InsecureConfiguration(
            "Refusing to start in production:\n  - " + "\n  - ".join(problems))


def summary() -> dict:
    """Non-secret view of the runtime posture, for logs and /api/health."""
    return {
        "environment": environment(),
        "debug": debug_enabled(),
        "https": https_enabled(),
        "demo_endpoints": demo_endpoints_enabled(),
        "otp_reveal": reveal_otp_enabled(),
        "cors_origins": cors_origins(),
        "aes_key_ephemeral": aes_key_is_ephemeral(),
    }

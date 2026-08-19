"""
AES-256-GCM field encryption for sensitive values at rest (phone numbers,
trusted-contact addresses).

FAIL CLOSED. An earlier version fell back to writing a `plain:`-prefixed value
when the `cryptography` package was missing, which meant a dependency problem
silently downgraded the system to storing plaintext PII while the UI continued
to claim encryption (finding F10). Encryption now either works or raises.

Key management: the 256-bit key comes from `SIMSHIELD_AES_KEY` (base64, 32
bytes). In development only, a per-process key is generated so the app runs
without setup — it is deliberately not persisted, so a restart rotates it and
previously encrypted values become undecryptable. That is a feature: it makes it
obvious that development data is disposable. Production refuses to start without
a supplied key (engine/settings.production_problems).

Storage format is `gcm:` + base64(nonce || ciphertext || tag). Each value
carries its own nonce, so the format is rotation-friendly.

📋 Production would hold this key in a KMS/HSM with scheduled rotation and
   envelope encryption; that is out of scope for a local prototype.
"""
import base64
import os

from . import settings

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAVE_AES = True
except Exception:  # pragma: no cover - exercised only without the dependency
    AESGCM = None
    _HAVE_AES = False

_PREFIX = "gcm:"
_key_cache: bytes | None = None


class CryptoUnavailable(RuntimeError):
    """Raised when encryption is required but cannot be performed."""


def is_available() -> bool:
    return _HAVE_AES


def _load_key() -> bytes:
    global _key_cache
    if _key_cache is not None:
        return _key_cache
    if not _HAVE_AES:
        raise CryptoUnavailable(
            "The `cryptography` package is not installed, so PII cannot be "
            "encrypted. Install it (pip install -r requirements.txt) — "
            "SIMShield will not store personal data in plaintext.")
    raw = base64.b64decode(settings.aes_key_b64())
    if len(raw) != 32:
        raise CryptoUnavailable(
            "SIMSHIELD_AES_KEY must decode to exactly 32 bytes for AES-256-GCM.")
    _key_cache = raw
    return _key_cache


def reset_key_cache() -> None:
    """Testing hook — forget the cached key so a new env var takes effect."""
    global _key_cache
    _key_cache = None


def encrypt(plaintext: str | None) -> str | None:
    """str -> 'gcm:' + b64(nonce || ciphertext+tag). None passes through."""
    if plaintext is None:
        return None
    aes = AESGCM(_load_key())
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return _PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt(token: str | None) -> str | None:
    """
    Reverse of encrypt(). Returns None for a value that cannot be decrypted
    (wrong key, corrupt record) rather than raising, so one unreadable row
    cannot take down a whole dashboard.
    """
    if token is None:
        return None
    if not token.startswith(_PREFIX):
        # Legacy `plain:` values from before this fix, or an unencrypted
        # migration artefact. Refuse to hand them back as if they were sound.
        if token.startswith("plain:"):
            return None
        return None
    try:
        raw = base64.b64decode(token[len(_PREFIX):])
        aes = AESGCM(_load_key())
        return aes.decrypt(raw[:12], raw[12:], None).decode("utf-8")
    except Exception:
        return None

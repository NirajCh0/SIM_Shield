"""
WebAuthn / passkeys — server-side ceremonies (improvement #5, part 2).

WHY PASSKEYS ARE THE RIGHT ANSWER TO SIM SWAP
Every other factor in this system is delivered to a phone number. A SIM swap
steals the phone number. That is not a weakness in the OTP implementation — it
is the OTP's threat model being wrong for this attack. A passkey is a private
key held by the subscriber's device or security key, bound to this origin, that
never travels over the mobile network and cannot be phished or replayed. It is
the only factor here that a successful SIM swap does not defeat.

WHAT IS AND IS NOT IMPLEMENTED
Implemented and tested: registration and authentication ceremonies, challenge
binding, origin and RP-ID checks, user-presence and user-verification flags,
signature verification for ES256 and RS256, and signature-counter regression
detection.

**Attestation is NOT verified.** The attestation statement is parsed, and the
format is recorded, but no trust chain is validated, so this accepts `none`
attestation and does not prove which authenticator model was used. That matches
what most consumer deployments do — attestation mainly matters to enterprises
enforcing hardware policy — but it is a real limitation and it is stated here
rather than implied to be absent.

**A registered domain and HTTPS are required in production.** WebAuthn binds
credentials to an RP ID, and browsers only allow it on secure origins
(`localhost` is exempt, which is why the demo works). A deployment needs a real
domain before any of this is meaningful.

WHY THIS IS HAND-WRITTEN
No WebAuthn library is available in this environment. The verification itself is
a small, well-specified set of checks over `authenticatorData || SHA-256(
clientDataJSON)`, and `cryptography` does the actual signature maths — nothing
cryptographic is invented here. The parsing is the risky part, so it is strict
(see `engine/cbor_min.py`) and every individual check has a negative test that
proves it rejects.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import threading
import time

from . import db, settings
from .cbor_min import CborError, loads, loads_prefix
from .config_loader import load_config

# --- authenticator-data flag bits ---------------------------------------------
FLAG_UP = 0x01          # user present
FLAG_UV = 0x04          # user verified (PIN/biometric)
FLAG_BE = 0x08          # backup eligible
FLAG_BS = 0x10          # backed up (synced passkey)
FLAG_AT = 0x40          # attested credential data included
FLAG_ED = 0x80          # extension data included

#: COSE algorithm identifiers this server accepts. Deliberately short: these
#: two cover essentially every real authenticator, and every additional
#: algorithm is another parser to get right.
ALG_ES256 = -7
ALG_RS256 = -257
SUPPORTED_ALGS = (ALG_ES256, ALG_RS256)

CHALLENGE_TTL_SECONDS = 300


class WebAuthnError(ValueError):
    """Any failed ceremony. The message is safe to show a user."""


# --- base64url ------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    if not isinstance(value, str):
        raise WebAuthnError("expected a base64url string")
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:                       # noqa: BLE001
        raise WebAuthnError("malformed base64url value") from exc


# --- configuration ---------------------------------------------------------------
def config() -> dict:
    cfg = load_config().get("webauthn") or {}
    return {
        "enabled": bool(cfg.get("enabled", True)),
        "rp_id": cfg.get("rp_id", "localhost"),
        "rp_name": cfg.get("rp_name", "SIMShield"),
        "origins": list(cfg.get("origins", ["http://localhost:5000",
                                            "http://127.0.0.1:5000"])),
        "user_verification": cfg.get("user_verification", "preferred"),
        "timeout_ms": int(cfg.get("timeout_ms", 60000)),
    }


def _rp_id_hash(rp_id: str) -> bytes:
    return hashlib.sha256(rp_id.encode("utf-8")).digest()


# --- challenge store ------------------------------------------------------------
# In-process, like the login-challenge store. A multi-worker deployment needs
# Redis; the prototype is single-process and says so.
_challenges: dict[str, dict] = {}
_lock = threading.Lock()


def _new_challenge(kind: str, user_id: int | None) -> tuple[str, bytes]:
    handle = secrets.token_urlsafe(16)
    challenge = os.urandom(32)
    with _lock:
        now = time.time()
        # Opportunistic sweep, so an abandoned ceremony cannot accumulate.
        for key, entry in list(_challenges.items()):
            if entry["expires"] < now:
                _challenges.pop(key, None)
        _challenges[handle] = {"challenge": challenge, "kind": kind,
                               "user_id": user_id,
                               "expires": now + CHALLENGE_TTL_SECONDS}
    return handle, challenge


def _take_challenge(handle: str, kind: str) -> dict:
    """
    Consume a challenge. Single-use: removed on read, so a captured response
    cannot be replayed even within the TTL.
    """
    with _lock:
        entry = _challenges.pop(handle, None)
    if not entry:
        raise WebAuthnError("This sign-in attempt expired. Please try again.")
    if entry["expires"] < time.time():
        raise WebAuthnError("This sign-in attempt expired. Please try again.")
    if entry["kind"] != kind:
        raise WebAuthnError("Challenge was issued for a different operation.")
    return entry


# --- parsing ---------------------------------------------------------------------
def parse_authenticator_data(data: bytes) -> dict:
    """
    Split authenticator data into its fixed layout.

    37 bytes of header, then attested credential data when the AT flag is set.
    Length is validated at every step: a short buffer must raise, not silently
    produce a truncated credential id.
    """
    if len(data) < 37:
        raise WebAuthnError("authenticator data is too short")
    flags = data[32]
    out = {
        "rp_id_hash": data[0:32],
        "flags": flags,
        "user_present": bool(flags & FLAG_UP),
        "user_verified": bool(flags & FLAG_UV),
        "backup_eligible": bool(flags & FLAG_BE),
        "backed_up": bool(flags & FLAG_BS),
        "sign_count": int.from_bytes(data[33:37], "big"),
        "credential_id": None,
        "public_key": None,
        "aaguid": None,
    }
    if not (flags & FLAG_AT):
        return out

    rest = data[37:]
    if len(rest) < 18:
        raise WebAuthnError("attested credential data is truncated")
    out["aaguid"] = rest[0:16].hex()
    cred_len = int.from_bytes(rest[16:18], "big")
    if cred_len == 0 or cred_len > 1023:
        raise WebAuthnError("invalid credential id length")
    if len(rest) < 18 + cred_len:
        raise WebAuthnError("credential id is truncated")
    out["credential_id"] = rest[18:18 + cred_len]
    try:
        key, _used = loads_prefix(rest[18 + cred_len:])
    except CborError as exc:
        raise WebAuthnError(f"malformed credential public key: {exc}") from exc
    if not isinstance(key, dict):
        raise WebAuthnError("credential public key is not a COSE map")
    out["public_key"] = key
    return out


def _check_client_data(raw: bytes, expected_type: str, challenge: bytes) -> dict:
    try:
        client = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise WebAuthnError("client data is not valid JSON") from exc
    if not isinstance(client, dict):
        raise WebAuthnError("client data is not an object")

    if client.get("type") != expected_type:
        # Prevents a registration response being replayed as an assertion.
        raise WebAuthnError(
            f"wrong ceremony type: expected {expected_type}, got {client.get('type')!r}")

    got = b64url_decode(client.get("challenge", ""))
    if not secrets.compare_digest(got, challenge):
        raise WebAuthnError("challenge did not match — possible replay")

    allowed = config()["origins"]
    if client.get("origin") not in allowed:
        raise WebAuthnError(
            f"origin {client.get('origin')!r} is not allowed for this deployment")
    if client.get("crossOrigin") is True:
        raise WebAuthnError("cross-origin WebAuthn ceremonies are refused")
    return client


def _load_public_key(cose: dict):
    """Turn a COSE key map into a `cryptography` public key object."""
    from cryptography.hazmat.primitives.asymmetric import ec, rsa

    kty = cose.get(1)
    alg = cose.get(3)
    if alg not in SUPPORTED_ALGS:
        raise WebAuthnError(f"unsupported credential algorithm {alg!r}")

    if alg == ALG_ES256:
        if kty != 2:
            raise WebAuthnError("ES256 credential is not an EC2 key")
        if cose.get(-1) != 1:
            raise WebAuthnError("ES256 credential is not on curve P-256")
        x, y = cose.get(-2), cose.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes):
            raise WebAuthnError("EC coordinates missing from the COSE key")
        if len(x) != 32 or len(y) != 32:
            raise WebAuthnError("EC coordinates are the wrong length for P-256")
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"),
            ec.SECP256R1()).public_key()

    if kty != 3:
        raise WebAuthnError("RS256 credential is not an RSA key")
    n, e = cose.get(-1), cose.get(-2)
    if not isinstance(n, bytes) or not isinstance(e, bytes):
        raise WebAuthnError("RSA parameters missing from the COSE key")
    if len(n) < 256:
        raise WebAuthnError("RSA modulus is shorter than 2048 bits")
    return rsa.RSAPublicNumbers(int.from_bytes(e, "big"),
                                int.from_bytes(n, "big")).public_key()


def _verify_signature(cose: dict, signature: bytes, signed: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding

    key = _load_public_key(cose)
    try:
        if cose.get(3) == ALG_ES256:
            key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        else:
            key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise WebAuthnError("signature verification failed") from exc


# --- registration ----------------------------------------------------------------
def registration_options(user: dict) -> dict:
    """Options for `navigator.credentials.create()`."""
    cfg = config()
    if not cfg["enabled"]:
        raise WebAuthnError("Passkeys are disabled in this deployment.")
    handle, challenge = _new_challenge("webauthn.create", user["id"])
    existing = [c["credential_id"] for c in list_credentials(user["id"])]
    return {
        "handle": handle,
        "publicKey": {
            "challenge": b64url_encode(challenge),
            "rp": {"id": cfg["rp_id"], "name": cfg["rp_name"]},
            "user": {
                # An opaque per-user handle, not the email: the user handle can
                # be stored on the authenticator and synced to a vendor cloud.
                "id": b64url_encode(hashlib.sha256(
                    f"simshield-user:{user['id']}".encode()).digest()[:16]),
                "name": user["email"],
                "displayName": user["display_name"],
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": a}
                                 for a in SUPPORTED_ALGS],
            "timeout": cfg["timeout_ms"],
            "attestation": "none",
            "excludeCredentials": [{"type": "public-key", "id": cid}
                                   for cid in existing],
            "authenticatorSelection": {
                "residentKey": "preferred",
                "userVerification": cfg["user_verification"],
            },
        },
    }


def register(user: dict, handle: str, credential: dict, label: str = "") -> dict:
    """Verify a `navigator.credentials.create()` response and store it."""
    entry = _take_challenge(handle, "webauthn.create")
    if entry["user_id"] != user["id"]:
        raise WebAuthnError("This registration challenge belongs to another account.")

    response = (credential or {}).get("response") or {}
    client_raw = b64url_decode(response.get("clientDataJSON", ""))
    _check_client_data(client_raw, "webauthn.create", entry["challenge"])

    try:
        attestation = loads(b64url_decode(response.get("attestationObject", "")))
    except CborError as exc:
        raise WebAuthnError(f"malformed attestation object: {exc}") from exc
    if not isinstance(attestation, dict) or "authData" not in attestation:
        raise WebAuthnError("attestation object is missing authenticator data")

    auth_data = attestation["authData"]
    if not isinstance(auth_data, bytes):
        raise WebAuthnError("authenticator data is not a byte string")
    parsed = parse_authenticator_data(auth_data)

    cfg = config()
    if parsed["rp_id_hash"] != _rp_id_hash(cfg["rp_id"]):
        raise WebAuthnError("this credential was created for a different site")
    if not parsed["user_present"]:
        raise WebAuthnError("the authenticator did not confirm user presence")
    if cfg["user_verification"] == "required" and not parsed["user_verified"]:
        raise WebAuthnError("this deployment requires PIN or biometric verification")
    if not parsed["credential_id"] or not parsed["public_key"]:
        raise WebAuthnError("the response contained no credential")

    # Validate the key now rather than at first sign-in, so an unusable
    # credential is rejected while the user is still on the enrolment screen.
    _load_public_key(parsed["public_key"])

    cred_id = b64url_encode(parsed["credential_id"])
    if db.query_one("SELECT id FROM webauthn_credentials WHERE credential_id = ?",
                    (cred_id,)):
        raise WebAuthnError("This passkey is already registered.")

    cred_row = db.execute(
        "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, "
        "sign_count, transports, label, aaguid, backed_up, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (user["id"], cred_id,
         b64url_encode(_encode_cose(parsed["public_key"])),
         parsed["sign_count"],
         json.dumps(credential.get("transports") or []),
         (label or "Passkey")[:60], parsed["aaguid"],
         1 if parsed["backed_up"] else 0, db.now()))
    db.log_activity(user["id"], "passkey_registered",
                    {"credential": cred_id[:12], "backed_up": parsed["backed_up"]})
    return {"id": cred_row, "credential_id": cred_id,
            "label": (label or "Passkey")[:60],
            "attestation_format": attestation.get("fmt"),
            "attestation_verified": False,
            "backed_up": parsed["backed_up"]}


def _encode_cose(cose: dict) -> bytes:
    """
    Re-serialise a COSE key for storage.

    A JSON round-trip through a dict with integer keys and byte values is
    lossy, so the key is stored in a small explicit binary form instead: the
    fields we need, tagged. This is storage-only and never parsed from
    untrusted input.
    """
    payload = {str(k): (b64url_encode(v) if isinstance(v, bytes) else v)
               for k, v in cose.items() if isinstance(k, int)}
    return json.dumps(payload, sort_keys=True).encode("utf-8")


def _decode_cose(stored: str) -> dict:
    payload = json.loads(b64url_decode(stored).decode("utf-8"))
    out: dict = {}
    for key, value in payload.items():
        k = int(key)
        # Byte-valued COSE labels: EC x/y and RSA n/e are all negative.
        out[k] = b64url_decode(value) if isinstance(value, str) and k < 0 else value
    return out


# --- authentication ---------------------------------------------------------------
def authentication_options(user: dict | None = None) -> dict:
    """Options for `navigator.credentials.get()`."""
    cfg = config()
    if not cfg["enabled"]:
        raise WebAuthnError("Passkeys are disabled in this deployment.")
    handle, challenge = _new_challenge("webauthn.get", user["id"] if user else None)
    allow = []
    if user:
        allow = [{"type": "public-key", "id": c["credential_id"]}
                 for c in list_credentials(user["id"])]
    return {
        "handle": handle,
        "publicKey": {
            "challenge": b64url_encode(challenge),
            "rpId": cfg["rp_id"],
            "timeout": cfg["timeout_ms"],
            "userVerification": cfg["user_verification"],
            "allowCredentials": allow,
        },
    }


def authenticate(handle: str, credential: dict) -> dict:
    """
    Verify a `navigator.credentials.get()` response.

    Returns {user_id, credential_id, user_verified, clone_warning}. The caller
    is responsible for creating the session — this function proves possession of
    the key and nothing else.
    """
    entry = _take_challenge(handle, "webauthn.get")

    cred_id = (credential or {}).get("id") or (credential or {}).get("rawId")
    if not cred_id:
        raise WebAuthnError("No credential was supplied.")
    row = db.query_one("SELECT * FROM webauthn_credentials WHERE credential_id = ?",
                       (cred_id,))
    if not row:
        raise WebAuthnError("This passkey is not registered on any account.")
    if entry["user_id"] is not None and entry["user_id"] != row["user_id"]:
        raise WebAuthnError("This passkey belongs to a different account.")

    response = (credential or {}).get("response") or {}
    client_raw = b64url_decode(response.get("clientDataJSON", ""))
    _check_client_data(client_raw, "webauthn.get", entry["challenge"])

    auth_data = b64url_decode(response.get("authenticatorData", ""))
    parsed = parse_authenticator_data(auth_data)

    cfg = config()
    if parsed["rp_id_hash"] != _rp_id_hash(cfg["rp_id"]):
        raise WebAuthnError("this passkey was issued for a different site")
    if not parsed["user_present"]:
        raise WebAuthnError("the authenticator did not confirm user presence")
    if cfg["user_verification"] == "required" and not parsed["user_verified"]:
        raise WebAuthnError("this deployment requires PIN or biometric verification")

    signed = auth_data + hashlib.sha256(client_raw).digest()
    _verify_signature(_decode_cose(row["public_key"]),
                      b64url_decode(response.get("signature", "")), signed)

    # Signature-counter regression suggests a cloned authenticator. Many modern
    # (synced) passkeys report a constant 0, so a non-increasing counter is only
    # meaningful when the authenticator uses counters at all — reporting it as a
    # warning rather than a refusal avoids locking out ordinary iCloud/Google
    # passkey users while still surfacing the signal.
    clone_warning = False
    if parsed["sign_count"] > 0 or row["sign_count"] > 0:
        if parsed["sign_count"] <= row["sign_count"]:
            clone_warning = True

    db.execute(
        "UPDATE webauthn_credentials SET sign_count = ?, last_used_at = ? WHERE id = ?",
        (max(parsed["sign_count"], row["sign_count"]), db.now(), row["id"]))
    db.log_activity(row["user_id"], "passkey_auth_ok",
                    {"credential": cred_id[:12], "clone_warning": clone_warning})
    if clone_warning:
        db.add_alert(row["user_id"], "account",
                     "A passkey signed in with a signature counter that did not "
                     "advance. This can mean the key was cloned. If this was not "
                     "you, remove the passkey and contact the bank.",
                     severity="critical")
    return {"user_id": row["user_id"], "credential_id": cred_id,
            "user_verified": parsed["user_verified"],
            "clone_warning": clone_warning}


# --- management --------------------------------------------------------------------
def list_credentials(user_id: int) -> list[dict]:
    return db.query_all(
        "SELECT id, credential_id, label, aaguid, backed_up, sign_count, "
        "created_at, last_used_at FROM webauthn_credentials WHERE user_id = ? "
        "ORDER BY id", (user_id,))


def delete_credential(user_id: int, cred_row_id: int) -> bool:
    with db.db() as con:
        cur = con.execute(
            "DELETE FROM webauthn_credentials WHERE id = ? AND user_id = ?",
            (cred_row_id, user_id))
        removed = cur.rowcount == 1
    if removed:
        db.log_activity(user_id, "passkey_removed", {"id": cred_row_id})
    return removed


def posture(user_id: int) -> dict:
    """What the subscriber should be told about their phone-independent factors."""
    from . import recovery_codes
    creds = list_credentials(user_id)
    codes = recovery_codes.status(user_id)
    return {
        "enabled": config()["enabled"],
        "rp_id": config()["rp_id"],
        "passkeys": len(creds),
        "credentials": creds,
        "recovery_codes": codes,
        "sim_swap_resistant": bool(creds) or codes["configured"],
        "attestation_verified": False,
        "advice": (
            "You have a way to sign in that does not depend on your phone number."
            if creds or codes["configured"] else
            "Every way of signing in to this account currently depends on your "
            "phone number — which is exactly what a SIM swap takes. Add a "
            "passkey or save recovery codes."),
        "limitations": [
            "Attestation is not verified, so the authenticator model is not proven.",
            "Requires HTTPS and a registered domain outside localhost.",
        ],
    }


def demo_supported() -> bool:
    """Whether this environment can run the passkey demo at all."""
    return config()["enabled"] and not settings.is_production()

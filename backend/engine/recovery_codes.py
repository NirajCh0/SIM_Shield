"""
Single-use recovery codes (improvement #5, part 1).

WHY THIS MATTERS SPECIFICALLY FOR SIM SWAP
Every other second factor in SIMShield travels over the mobile network, which is
precisely the channel a SIM swap steals. A victim mid-attack is in the worst
possible position: the attacker holds their number, so the "recover your
account" flow delivers its code to the attacker. Recovery codes are the one
factor that is already in the subscriber's hands before the attack starts, so
they still work when the phone number does not.

DESIGN
  * 10 codes,
    generated once, displayed once, never recoverable afterwards.
  * Stored as PBKDF2-SHA-256 hashes with per-code salt, verified in constant
    time. A leaked database must not yield usable codes.
  * Single use, claimed atomically — two concurrent requests cannot spend the
    same code (the same class of bug as the double-release finding F15).
  * Regenerating invalidates every previous code, so a subscriber who suspects
    their printout was seen has a way to act.

FORMAT
Base32 without the ambiguous characters, in two groups: `K7M4Q-9XPT2`. It is
meant to be written on paper and typed by a stressed person, so I/O/0/1 are
excluded and comparison is case-insensitive and separator-insensitive.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets

from . import db

#: No I, O, 0 or 1 — those are the pairs people mistype from paper.
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
GROUP_LEN = 5
GROUPS = 2
CODE_COUNT = 10
PBKDF2_ROUNDS = 200_000


def _format(raw: str) -> str:
    return "-".join(raw[i:i + GROUP_LEN] for i in range(0, len(raw), GROUP_LEN))


def normalise(code: str) -> str:
    """
    Strip separators and case before comparison.

    Someone reading a code off paper during an account takeover should not fail
    because they typed a space instead of a hyphen.
    """
    return "".join(ch for ch in (code or "").upper()
                   if ch in ALPHABET)


def generate_code() -> str:
    raw = "".join(secrets.choice(ALPHABET) for _ in range(GROUP_LEN * GROUPS))
    return _format(raw)


def _hash(code: str, salt: bytes) -> str:
    digest = hashlib.pbkdf2_hmac("sha256", normalise(code).encode("utf-8"),
                                 salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${salt.hex()}${digest.hex()}"


def _verify(code: str, stored: str) -> bool:
    try:
        algo, rounds, salt_hex, digest_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        expected = hashlib.pbkdf2_hmac("sha256", normalise(code).encode("utf-8"),
                                       bytes.fromhex(salt_hex), int(rounds))
        return hmac.compare_digest(expected.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def generate_for_user(user_id: int, count: int = CODE_COUNT) -> list[str]:
    """
    Issue a fresh set, invalidating any previous set.

    Returns the PLAINTEXT codes. This is the only moment they exist in
    readable form — the caller must show them once and must not log them.
    """
    codes = [generate_code() for _ in range(count)]
    with db.db() as con:
        con.execute("BEGIN IMMEDIATE")
        con.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
        for code in codes:
            con.execute(
                "INSERT INTO recovery_codes (user_id, code_hash, created_at) "
                "VALUES (?,?,?)", (user_id, _hash(code, os.urandom(16)), db.now()))
    db.log_activity(user_id, "recovery_codes_generated", {"count": len(codes)})
    return codes


def remaining(user_id: int) -> int:
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
        (user_id,))
    return (row or {}).get("n", 0)


def status(user_id: int) -> dict:
    total = (db.query_one("SELECT COUNT(*) AS n FROM recovery_codes WHERE user_id = ?",
                          (user_id,)) or {}).get("n", 0)
    left = remaining(user_id)
    return {
        "configured": total > 0,
        "remaining": left,
        "total": total,
        "low": total > 0 and left <= 2,
    }


def consume(user_id: int, code: str) -> bool:
    """
    Spend one code. Returns True if it was valid and previously unused.

    The claim is atomic: the row is marked used inside the same immediate
    transaction that selected it, so two requests racing with the same code
    cannot both succeed. Codes are compared in constant time, and a failure
    never reveals whether the code was wrong or already spent.
    """
    if not normalise(code):
        return False
    with db.db() as con:
        con.execute("BEGIN IMMEDIATE")
        rows = con.execute(
            "SELECT id, code_hash FROM recovery_codes WHERE user_id = ? "
            "AND used_at IS NULL", (user_id,)).fetchall()
        for row in rows:
            if _verify(code, row["code_hash"]):
                cur = con.execute(
                    "UPDATE recovery_codes SET used_at = ? "
                    "WHERE id = ? AND used_at IS NULL", (db.now(), row["id"]))
                if cur.rowcount == 1:
                    used = True
                    break
        else:
            used = False
    if used:
        # Logged outside the transaction: log_activity opens its own connection,
        # and doing that inside a write transaction self-deadlocks (the bug
        # found during the atomicity work).
        db.log_activity(user_id, "recovery_code_used",
                        {"remaining": remaining(user_id)})
    return used

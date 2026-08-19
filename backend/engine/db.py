"""
SQLite persistence layer for SIMShield's account / banking side.

The DETECTION side (profiles, scoring) stays file+config driven so the engine
remains a standalone library; everything ACCOUNT-shaped (auth, devices,
sim events, transactions, alerts, chat logs, notification outbox, activity)
lives here in one SQLite database.

Production would swap this for PostgreSQL + Redis; the schema below mirrors the
tables named in the project brief (users, sim_events, transactions, alerts,
chat_logs) plus the operational tables 2FA needs (otp_codes, sessions, devices,
outbox, activity_log). SQLite keeps the prototype dependency-free.

Privacy: identifiers follow the same rules as the rest of SIMShield —
phone numbers are AES-256-GCM encrypted at rest (engine.crypto), IMEI/IMSI are
stored only as salted hashes (engine.privacy), and passwords are PBKDF2 hashes.
"""
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime

from .config_loader import backend_path

DB_PATH = backend_path("data", "simshield.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT UNIQUE NOT NULL,
    password_hash   TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    role            TEXT NOT NULL DEFAULT 'user',      -- user | admin
    phone_enc       TEXT,                              -- AES-256-GCM encrypted
    operator        TEXT,                              -- NTC | NCELL | SMART
    profile_id      TEXT,                              -- linked synthetic detection profile
    language        TEXT NOT NULL DEFAULT 'en',        -- en | ne
    frozen          INTEGER NOT NULL DEFAULT 0,
    twofa_enabled   INTEGER NOT NULL DEFAULT 1,
    prefs           TEXT NOT NULL DEFAULT '{}',        -- notification preferences JSON
    points          INTEGER NOT NULL DEFAULT 0,
    badges          TEXT NOT NULL DEFAULT '[]',
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    balance         REAL NOT NULL DEFAULT 150000,      -- synthetic NPR balance
    trusted_contact_enc TEXT,                          -- AES-256-GCM encrypted email
    safe_zones      TEXT NOT NULL DEFAULT '[]',        -- user-managed geo-fence JSON
    created_at      TEXT NOT NULL,
    last_login      TEXT
);

CREATE TABLE IF NOT EXISTS otp_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    purpose    TEXT NOT NULL,          -- login | reset | unfreeze | txnrelease
    challenge  TEXT,                   -- pseudonymised login-challenge binding
    expires_at TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    used       INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token            TEXT PRIMARY KEY,
    user_id          INTEGER NOT NULL REFERENCES users(id),
    fingerprint_hash TEXT,
    ip               TEXT,
    csrf_token       TEXT,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER NOT NULL REFERENCES users(id),
    fingerprint_hash TEXT NOT NULL,
    label            TEXT,
    trusted          INTEGER NOT NULL DEFAULT 0,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    UNIQUE(user_id, fingerprint_hash)
);

CREATE TABLE IF NOT EXISTS sim_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    event_type  TEXT NOT NULL,         -- sim_activated | sim_swap | imsi_change | iccid_change
    operator    TEXT,
    imsi_hash   TEXT,                  -- pseudonymised (engine.privacy.hash_id)
    imei_hash   TEXT,
    risk_score  REAL,
    details     TEXT,
    occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS transactions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    amount        REAL NOT NULL,
    currency      TEXT NOT NULL DEFAULT 'NPR',
    merchant      TEXT,
    category      TEXT,
    flagged       INTEGER NOT NULL DEFAULT 0,
    anomaly_score REAL,
    reasons       TEXT NOT NULL DEFAULT '[]',
    status        TEXT NOT NULL DEFAULT 'posted',   -- posted | held | refused | released
    occurred_at   TEXT NOT NULL
);

-- Sign-in locations, deliberately COARSE. No latitude/longitude column exists
-- here by design: a precise fix is reduced to an area label plus a distance
-- band (engine/geo.coarse_area) before anything is written, so the subscriber
-- can recognise an impostor without the app becoming a movement history.
CREATE TABLE IF NOT EXISTS login_locations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    area       TEXT,             -- e.g. "Pokhara"
    country    TEXT,             -- e.g. "Nepal"
    band       TEXT,             -- e.g. "100-500 km" from a safe zone
    decision   TEXT,             -- ALLOW | MONITOR | VERIFY | BLOCK
    risk_score REAL,
    sim_area   TEXT,             -- operator-reported SIM area, when available
    mismatch   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    score      REAL NOT NULL,
    level      TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),
    alert_type TEXT NOT NULL,          -- sim_swap | login_risk | transaction | escalation | account
    severity   TEXT NOT NULL DEFAULT 'info',   -- info | warning | critical
    message    TEXT NOT NULL,
    channels   TEXT NOT NULL DEFAULT '[]',
    status     TEXT NOT NULL DEFAULT 'new',    -- new | acknowledged | escalated | resolved
    meta       TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS chat_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),  -- NULL for anonymous visitors
    lang       TEXT NOT NULL DEFAULT 'en',
    query      TEXT NOT NULL,
    intent     TEXT,
    response   TEXT NOT NULL,
    escalated  INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),
    channel    TEXT NOT NULL,          -- email | sms | push
    to_masked  TEXT,
    subject    TEXT,
    body       TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'simulated',   -- simulated | sent | failed
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS activity_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER REFERENCES users(id),
    action     TEXT NOT NULL,          -- login_ok | login_fail | otp_sent | otp_ok | freeze | ...
    meta       TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

-- --- Fraud-analyst case management (improvement #2) --------------------------
-- "Human-in-the-loop" is only a real control if the human's decision is
-- recorded in a form someone else can review. A case carries a CODED outcome
-- from a fixed taxonomy (reason_codes.yaml) rather than free text, so decisions
-- can be counted, audited and disagreed with.
CREATE TABLE IF NOT EXISTS cases (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER REFERENCES users(id),
    alert_id      INTEGER REFERENCES alerts(id),
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL DEFAULT 'medium',    -- low | medium | high | critical
    status        TEXT NOT NULL DEFAULT 'open',      -- open | investigating | awaiting_customer | resolved
    outcome       TEXT,                              -- set only on resolution
    reason_code   TEXT,                              -- from the fixed taxonomy
    opened_by     TEXT NOT NULL DEFAULT 'system',    -- system | admin:<id>
    assigned_to   INTEGER REFERENCES users(id),
    risk_score    REAL,
    decision      TEXT,                              -- ALLOW | MONITOR | VERIFY | BLOCK
    source        TEXT NOT NULL DEFAULT 'detector',  -- detector | appeal | manual
    due_at        TEXT,                              -- SLA target
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    resolved_at   TEXT
);

CREATE TABLE IF NOT EXISTS case_notes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id    INTEGER NOT NULL REFERENCES cases(id),
    author_id  INTEGER REFERENCES users(id),
    kind       TEXT NOT NULL DEFAULT 'note',   -- note | status | outcome | assignment | appeal
    body       TEXT NOT NULL,
    meta       TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

-- --- Subscriber appeals / false-positive feedback (improvement #3) -----------
-- The evaluation reports a false-positive rate; without a way for the person
-- wrongly stopped to say so, that number can never be checked against reality.
-- An upheld appeal is a LABEL, and engine/feedback.py turns those labels into
-- the measured false-positive rate.
CREATE TABLE IF NOT EXISTS appeals (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    case_id       INTEGER REFERENCES cases(id),
    decision      TEXT,                       -- the decision being appealed
    risk_score    REAL,
    context       TEXT NOT NULL DEFAULT '{}', -- minimised, no raw location
    statement     TEXT NOT NULL,              -- the subscriber's own words
    status        TEXT NOT NULL DEFAULT 'submitted',  -- submitted | reviewing | upheld | rejected | withdrawn
    outcome_note  TEXT,
    reviewed_by   INTEGER REFERENCES users(id),
    created_at    TEXT NOT NULL,
    resolved_at   TEXT
);

-- --- Passkeys and recovery codes (improvement #5) ----------------------------
-- Both exist for the same reason: an SMS OTP is the exact thing a SIM swap
-- steals, so a second factor that does not travel over the mobile network is
-- the structural answer rather than a better OTP.
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id),
    credential_id TEXT NOT NULL UNIQUE,       -- base64url
    public_key    TEXT NOT NULL,              -- COSE key, base64url
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT NOT NULL DEFAULT '[]',
    label         TEXT,
    aaguid        TEXT,
    backed_up     INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    code_hash  TEXT NOT NULL,      -- PBKDF2, never the code itself
    used_at    TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_user   ON alerts(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_cases_status  ON cases(status, created_at);
CREATE INDEX IF NOT EXISTS idx_cases_user    ON cases(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_notes_case    ON case_notes(case_id, created_at);
CREATE INDEX IF NOT EXISTS idx_appeals_user  ON appeals(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_appeals_state ON appeals(status, created_at);
CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id, used_at);
CREATE INDEX IF NOT EXISTS idx_txn_user      ON transactions(user_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_log(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_chat_user     ON chat_logs(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_sim_user      ON sim_events(user_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_loginloc_user ON login_locations(user_id, created_at);
"""


def now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def connect() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    # isolation_level=None puts the driver in autocommit mode so callers can
    # open explicit transactions with BEGIN IMMEDIATE. That matters for the
    # financial simulation: the debit and the ledger insert must commit together
    # or not at all (finding F14). timeout lets a writer wait for the lock
    # instead of failing immediately under concurrency.
    con = sqlite3.connect(DB_PATH, timeout=10.0, isolation_level=None)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA busy_timeout=10000")
    return con


# Columns added after the first release: ALTER-based migration keeps existing
# databases working without a wipe. (name, table, DDL fragment)
_MIGRATIONS = [
    ("users", "balance", "REAL NOT NULL DEFAULT 150000"),
    ("users", "trusted_contact_enc", "TEXT"),
    ("users", "safe_zones", "TEXT NOT NULL DEFAULT '[]'"),
    ("transactions", "status", "TEXT NOT NULL DEFAULT 'posted'"),
    ("otp_codes", "challenge", "TEXT"),
    ("sessions", "csrf_token", "TEXT"),
]


def init_db() -> None:
    with connect() as con:
        con.executescript(_SCHEMA)
        for table, col, ddl in _MIGRATIONS:
            cols = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
            if col not in cols:
                con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")


@contextmanager
def db():
    """
    Connection scope. In autocommit mode single statements commit themselves;
    a block that opens BEGIN IMMEDIATE is committed here, or rolled back if the
    body raises so a half-applied financial simulation can never persist.
    """
    con = connect()
    try:
        yield con
        if con.in_transaction:
            con.commit()
    except Exception:
        if con.in_transaction:
            con.rollback()
        raise
    finally:
        con.close()


# --- tiny row helpers ---------------------------------------------------------
def row_to_dict(row: sqlite3.Row | None) -> dict | None:
    return dict(row) if row is not None else None


def rows_to_dicts(rows) -> list[dict]:
    return [dict(r) for r in rows]


def query_one(sql: str, params=()) -> dict | None:
    with db() as con:
        return row_to_dict(con.execute(sql, params).fetchone())


def query_all(sql: str, params=()) -> list[dict]:
    with db() as con:
        return rows_to_dicts(con.execute(sql, params).fetchall())


def execute(sql: str, params=()) -> int:
    """Run an INSERT/UPDATE/DELETE; returns lastrowid."""
    with db() as con:
        cur = con.execute(sql, params)
        return cur.lastrowid


def log_activity(user_id: int | None, action: str, meta: dict | None = None) -> None:
    execute(
        "INSERT INTO activity_log (user_id, action, meta, created_at) VALUES (?,?,?,?)",
        (user_id, action, json.dumps(meta or {}), now()),
    )


def add_alert(user_id: int | None, alert_type: str, message: str,
              severity: str = "warning", channels: list | None = None,
              meta: dict | None = None, status: str = "new") -> int:
    return execute(
        "INSERT INTO alerts (user_id, alert_type, severity, message, channels, status, meta, created_at) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (user_id, alert_type, severity, message, json.dumps(channels or []),
         status, json.dumps(meta or {}), now()),
    )

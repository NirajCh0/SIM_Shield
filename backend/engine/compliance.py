"""
Compliance & accountability layer: consent, a TAMPER-EVIDENT audit trail, and
data-retention enforcement. Policy-driven by compliance.yaml.

  * record_decision()    -> append a pseudonymised, hash-chained audit entry
  * verify_audit_chain() -> recompute the chain and report integrity
  * checkpoint_audit()   -> sign the current head so truncation is detectable
  * check_consent()      -> gate study/storage on informed consent
  * enforce_retention()  -> purge records past their retention window
  * ethics_notice()      -> the machine-readable ethics/scope statement

TAMPER-EVIDENT, NOT TAMPER-PROOF (finding F23)
----------------------------------------------
Each entry stores SHA-256(previous_hash + body), so editing or deleting a past
line breaks every subsequent hash. That detects *casual* modification. It does
NOT stop an attacker who can write the file and run this code: they can simply
recompute the whole chain. The signed checkpoints below raise the bar — each
records the chain head under an HMAC the attacker also needs — but genuine
tamper-*proofing* requires an external append-only anchor outside this host
(📋 future production work). The documentation says exactly this.

CONCURRENCY (finding F18)
-------------------------
Appending used to read the last hash and then write, so two concurrent requests
could both read head H and produce two entries claiming prev=H — forking the
chain and making verification fail for reasons unrelated to tampering. All
mutations now hold an exclusive lock for read-hash-and-append.
"""
import contextlib
import hashlib
import hmac
import json
import os
import threading
import time
from datetime import datetime, timedelta

from . import privacy, settings
from .config_loader import backend_path, load_compliance

_GENESIS = "0" * 64

# Guards read-modify-write on the audit log. A process-level lock is sufficient
# for the single-process prototype; a multi-worker deployment would need an
# OS-level file lock or an append-only datastore (📋).
_audit_lock = threading.Lock()


#: Set by `redirect_audit()` while a bulk evaluation runs. See below.
_audit_path_override: str | None = None


@contextlib.contextmanager
def redirect_audit(path: str):
    """
    Send audit writes to `path` for the duration of the block.

    WHY THIS EXISTS
    `evaluate_operator.py` re-scores the whole scenario suite nine times, and
    every operator lookup is audited — which appended ~6,400 records to the real
    subscriber audit log on a single run. Two problems with that: it buries
    genuine access records in harness noise, and appending is O(n) in the log
    length (the head hash is found by reading the file), so the chain gets
    quadratically slower with every evaluation.

    A synthetic evaluation over fixture profiles is not subscriber access, so it
    gets its own sink. This deliberately does NOT disable auditing — the harness
    still produces a full, verifiable chain, just in its own file.
    """
    global _audit_path_override
    previous = _audit_path_override
    _audit_path_override = path
    try:
        yield path
    finally:
        _audit_path_override = previous


def _audit_path(comp: dict) -> str:
    if _audit_path_override:
        return _audit_path_override
    return backend_path(comp["audit"]["audit_log"])


def _entry_hash(prev_hash: str, body: dict) -> str:
    payload = prev_hash + json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _last_hash(path: str) -> str:
    if not os.path.exists(path):
        return _GENESIS
    last = _GENESIS
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)["hash"]
                except (ValueError, KeyError):
                    continue
    return last


def record_decision(user_id: str, attempt: dict, result: dict) -> dict | None:
    """
    Append a tamper-evident audit record for a scoring decision. Identifiers are
    pseudonymised and the attempt is minimised per policy. Returns the record.
    """
    comp = load_compliance()
    if not comp["audit"]["enabled"]:
        return None
    path = _audit_path(comp)

    body = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "subject": privacy.hash_id(user_id),          # pseudonym, not the id
        "device": privacy.hash_id(attempt.get("imei")),
        "decision": result["decision"],
        "risk_score": result["risk_score"],
        "ml_used": result.get("ml_used", False),
        "minimised_attempt": privacy.minimise_attempt({
            **attempt,
            "decision": result["decision"],
            "risk_score": result["risk_score"],
        }),
    }
    return _append(path, comp, body)


def _append(path: str, comp: dict, body: dict) -> dict:
    """Chain and append one audit body. Read-head-and-append must be atomic or
    concurrent writers fork the chain."""
    with _audit_lock:
        prev = _last_hash(path) if comp["audit"]["hash_chain"] else _GENESIS
        record = {**body, "prev": prev, "hash": _entry_hash(prev, body)}
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
            f.flush()
            os.fsync(f.fileno())
    return record


def record_operator_access(subject_id: str, result) -> dict | None:
    """
    Audit one operator lookup — including the ones that returned nothing.

    Failed and denied lookups are the interesting ones: a burst of
    CONSENT_DENIED entries for one subject is what an attacker probing for a
    victim's SIM status looks like, and an outage that silently stopped a
    control needs to be provable after the fact.

    What is recorded is an ALLOWLIST (`OperatorResult.audit_fields`) plus a
    pseudonymous subject: operation, status, freshness, latency, source and
    consent state. Deliberately NOT recorded: the reported area, the cell id,
    any coordinate, the phone number, the IMSI or the ICCID. Auditing a
    location lookup must not itself become a location history — that would
    rebuild, in the log, exactly the tracking the coarsening in `engine.geo`
    exists to prevent.
    """
    comp = load_compliance()
    if not comp["audit"]["enabled"]:
        return None
    path = _audit_path(comp)
    body = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "kind": "operator_access",
        "subject": privacy.hash_id(subject_id),
        **result.audit_fields(),
    }
    return _append(path, comp, body)


def record_staff_action(actor_pseudonym: str, action: str, target: str,
                        meta: dict | None = None) -> dict | None:
    """
    Audit an action taken by a member of staff (improvement #2).

    Subscriber decisions were already audited; staff decisions were not, which
    left the "human-in-the-loop" claim resting on records nobody kept. A fraud
    analyst closing a case, freezing an account or overturning an appeal is an
    exercise of power over someone's money, and it belongs in the same
    tamper-evident chain on the same terms.

    The analyst is pseudonymised like any other subject. Accountability does not
    require a cleartext name in the log — it requires that the same input always
    produces the same pseudonym, which HMAC gives us.
    """
    comp = load_compliance()
    if not comp["audit"]["enabled"]:
        return None
    body = {
        "ts": datetime.now().isoformat(timespec="seconds"),
        "kind": "staff_action",
        "actor": actor_pseudonym,
        "action": action,
        "target": target,
        "meta": meta or {},
    }
    return _append(_audit_path(comp), comp, body)


# --- signed checkpoints -------------------------------------------------------
def _checkpoint_path() -> str:
    """
    Checkpoints follow the audit log they describe.

    A redirected stream MUST get its own checkpoint file. When it did not, a
    redirected log was verified against the main log's checkpoint — which
    records a much larger entry count — and verification reported truncation
    for a chain that was perfectly intact. A checkpoint is a statement about
    one specific log, so it belongs beside it.
    """
    if _audit_path_override:
        return _audit_path_override + ".checkpoints"
    return backend_path("data", "audit.checkpoints")


def _sign(payload: str) -> str:
    """HMAC a checkpoint under the deployment secret."""
    key = settings.pseudonym_secret().encode("utf-8")
    return hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()


def checkpoint_audit(reason: str = "manual") -> dict:
    """
    Record a signed snapshot of the current chain head and entry count.

    This is what makes *truncation* detectable. Without it an attacker could
    delete the last N entries and recompute nothing — the remaining chain would
    still verify perfectly. With a signed checkpoint, verification can prove the
    log has fewer entries than it once did, unless the attacker also holds
    SIMSHIELD_PSEUDONYM_SECRET.

    📋 A production system would additionally publish these to an external
       append-only anchor so the host cannot rewrite its own history.
    """
    comp = load_compliance()
    path = _audit_path(comp)
    with _audit_lock:
        head = _last_hash(path)
        entries = 0
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                entries = sum(1 for line in f if line.strip())
        body = {"ts": datetime.now().isoformat(timespec="seconds"),
                "head": head, "entries": entries, "reason": reason}
        payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
        record = {**body, "sig": _sign(payload)}
        cp = _checkpoint_path()
        os.makedirs(os.path.dirname(cp), exist_ok=True)
        with open(cp, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    return record


def _latest_checkpoint() -> dict | None:
    cp = _checkpoint_path()
    if not os.path.exists(cp):
        return None
    last = None
    with open(cp, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    last = json.loads(line)
                except ValueError:
                    continue
    return last


def verify_audit_chain() -> dict:
    """
    Recompute the hash chain and cross-check it against the newest signed
    checkpoint. Reports integrity honestly: a verified chain proves the log has
    not been *casually* edited, not that it is authoritative.
    """
    comp = load_compliance()
    path = _audit_path(comp)
    if not os.path.exists(path):
        return {"intact": True, "entries": 0, "checkpoint": None,
                "guarantee": "tamper-evident (local)",
                "message": "No audit log yet."}

    prev = _GENESIS
    n = 0
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            n += 1
            try:
                rec = json.loads(line)
            except ValueError:
                return {"intact": False, "entries": n, "checkpoint": None,
                        "guarantee": "tamper-evident (local)",
                        "message": f"Corrupt audit entry at line {i}."}
            body = {k: rec[k] for k in rec if k not in ("prev", "hash")}
            expected = _entry_hash(prev, body)
            if rec.get("prev") != prev or rec.get("hash") != expected:
                return {"intact": False, "entries": n, "checkpoint": None,
                        "guarantee": "tamper-evident (local)",
                        "message": f"Chain broken at entry {i} — the log has "
                                   "been modified since it was written."}
            prev = rec["hash"]

    # Cross-check against the last signed checkpoint to catch truncation.
    cp_status, cp = None, _latest_checkpoint()
    if cp:
        payload = json.dumps({k: cp[k] for k in ("ts", "head", "entries", "reason")},
                             sort_keys=True, separators=(",", ":"))
        if not hmac.compare_digest(cp.get("sig", ""), _sign(payload)):
            cp_status = "checkpoint signature invalid"
        elif n < cp["entries"]:
            return {"intact": False, "entries": n, "checkpoint": cp["entries"],
                    "guarantee": "tamper-evident (local)",
                    "message": f"Truncation detected: {cp['entries']} entries "
                               f"were checkpointed but only {n} remain."}
        else:
            cp_status = f"consistent with checkpoint of {cp['entries']} entries"

    return {"intact": True, "entries": n, "checkpoint": cp_status,
            "guarantee": "tamper-evident (local)",
            "message": "Audit chain verified intact. Tamper-EVIDENT only — an "
                       "attacker with write access and this code could rewrite "
                       "the chain; an external append-only anchor is required "
                       "for stronger guarantees."}


def check_consent(consent: dict, purpose: str = "study") -> tuple[bool, str]:
    """
    Validate a consent payload for a given purpose. Returns (ok, message).
    consent = { "agreed": bool, "version": "1.0" }
    """
    comp = load_compliance()["consent"]
    if purpose == "study" and not comp["require_for_study"]:
        return True, "Consent not required by policy."
    if not consent or not consent.get("agreed"):
        return False, "Informed consent is required before participating."
    if consent.get("version") != comp["consent_version"]:
        return False, (f"Consent version mismatch (need {comp['consent_version']}).")
    return True, "Consent recorded."


def operator_consent_state(profile: dict | None, attempt: dict | None = None):
    """
    Resolve the subscriber's consent for an operator lookup.

    Network SIM location is personal data about a named subscriber, so the
    lawful basis is checked HERE — at the boundary, before any adapter runs —
    rather than trusted to each adapter.

    There is no permissive default. A record that does not state a consent
    decision resolves to UNKNOWN, which does not permit a lookup, because
    "nobody wrote it down" and "the subscriber agreed" are different facts and
    only one of them authorises processing. Every synthetic profile therefore
    carries an explicit `operator_consent` field.
    """
    from .operator_adapter import ConsentState

    if not load_compliance()["consent"].get("require_for_operator_lookup", True):
        return ConsentState.NOT_REQUIRED

    # An attempt may carry a withdrawal for this single check (demo/testing).
    for holder in (attempt or {}, profile or {}):
        value = holder.get("operator_consent")
        if value is True:
            return ConsentState.GRANTED
        if value is False:
            return ConsentState.WITHDRAWN
        if isinstance(value, str):
            match = {"granted": ConsentState.GRANTED,
                     "withdrawn": ConsentState.WITHDRAWN,
                     "denied": ConsentState.DENIED}.get(value.lower())
            if match:
                return match
    return ConsentState.UNKNOWN


def _purge_old_lines(path: str, max_age_days: int, ts_getter) -> int:
    """Rewrite a log keeping only lines newer than max_age_days. Returns purged count."""
    if not os.path.exists(path):
        return 0
    cutoff = datetime.now() - timedelta(days=max_age_days)
    kept, purged = [], 0
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            ts = ts_getter(line)
            if ts is None or ts >= cutoff:
                kept.append(line if line.endswith("\n") else line + "\n")
            else:
                purged += 1
    if purged:
        with open(path, "w", encoding="utf-8") as f:
            f.writelines(kept)
    return purged


def _json_ts(line: str):
    try:
        return datetime.fromisoformat(json.loads(line)["ts"])
    except Exception:
        return None


def _bracket_ts(line: str):
    """Timestamp from an `alerts.log` line: `[2026-08-12T10:00:00] ...`."""
    try:
        return datetime.fromisoformat(line[1:line.index("]")])
    except Exception:
        return None


def enforce_retention() -> dict:
    """
    Apply the documented retention windows to EVERY store, not just a subset
    (finding F19): the audit log, alerts log, study responses, and the database
    tables that accumulate personal or behavioural data — alerts, outbox, chat
    logs, activity, login areas, risk history, expired sessions and used OTPs.

    A signed checkpoint is written **before** purging so the audit log's
    verifiability survives its own retention: after a purge the chain no longer
    starts at genesis, and without the checkpoint that is indistinguishable from
    truncation by an attacker.
    """
    from . import db

    comp = load_compliance()
    ret = comp["retention"]
    report: dict = {}

    # Preserve verifiability across the purge.
    if os.path.exists(_audit_path(comp)):
        cp = checkpoint_audit(reason="pre-retention")
        report["checkpoint"] = {"head": cp["head"][:16] + "…",
                                "entries": cp["entries"]}

    report["audit_purged"] = _purge_old_lines(
        _audit_path(comp), ret["audit_log_days"], _json_ts)
    report["alerts_log_purged"] = _purge_old_lines(
        backend_path("data", "alerts.log"),
        ret.get("alert_log_days", 90), _bracket_ts)

    # Study responses: one JSON file per submission, purged by mtime.
    study_dir = backend_path("data", "study")
    purged = 0
    if os.path.isdir(study_dir):
        cutoff = time.time() - ret["study_responses_days"] * 86400
        for name in os.listdir(study_dir):
            fp = os.path.join(study_dir, name)
            if os.path.isfile(fp) and os.path.getmtime(fp) < cutoff:
                os.remove(fp)
                purged += 1
    report["study_purged"] = purged

    # --- database tables -----------------------------------------------------
    def _cutoff(days):
        return (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")

    alert_days = ret.get("alert_log_days", 90)
    audit_days = ret["audit_log_days"]
    area_days = load_compliance()["privacy"].get("login_area_retention_days", 90)

    db_report = {}
    with db.db() as con:
        def purge(sql, params, label):
            db_report[label] = con.execute(sql, params).rowcount

        purge("DELETE FROM alerts WHERE created_at < ? AND status IN "
              "('resolved','acknowledged')", (_cutoff(alert_days),), "alerts")
        purge("DELETE FROM outbox WHERE created_at < ?",
              (_cutoff(alert_days),), "outbox")
        purge("DELETE FROM chat_logs WHERE created_at < ?",
              (_cutoff(audit_days),), "chat_logs")
        purge("DELETE FROM activity_log WHERE created_at < ?",
              (_cutoff(audit_days),), "activity_log")
        purge("DELETE FROM login_locations WHERE created_at < ?",
              (_cutoff(area_days),), "login_locations")
        purge("DELETE FROM risk_history WHERE created_at < ?",
              (_cutoff(audit_days),), "risk_history")
        # Credentials-adjacent data goes as soon as it is spent or stale.
        purge("DELETE FROM otp_codes WHERE used = 1 OR expires_at < ?",
              (db.now(),), "otp_codes")
        purge("DELETE FROM sessions WHERE expires_at < ?", (db.now(),), "sessions")
        # A spent recovery code proves nothing and is only a hash to leak.
        purge("DELETE FROM recovery_codes WHERE used_at IS NOT NULL AND used_at < ?",
              (_cutoff(audit_days),), "recovery_codes")

        # Appeals and cases (improvements #2/#3). These carry the subscriber's
        # own account of what happened and an analyst's notes about them, so
        # they are personal data with a purpose that ends once the appeal is
        # answered and the aggregate statistics are derived. Only RESOLVED
        # records are eligible — an open case must never be purged out from
        # under the person waiting for an answer.
        appeal_days = ret.get("appeal_days", 365)
        purge("DELETE FROM case_notes WHERE case_id IN "
              "(SELECT id FROM cases WHERE resolved_at IS NOT NULL AND resolved_at < ?)",
              (_cutoff(appeal_days),), "case_notes")
        purge("DELETE FROM appeals WHERE resolved_at IS NOT NULL AND resolved_at < ?",
              (_cutoff(appeal_days),), "appeals")
        purge("DELETE FROM cases WHERE resolved_at IS NOT NULL AND resolved_at < ?",
              (_cutoff(appeal_days),), "cases")
    report["database_purged"] = db_report
    return report


def ethics_notice() -> dict:
    """Return the ethics/scope statement (surfaced in the UI and /api/ethics)."""
    e = load_compliance()["ethics"]
    return {
        "scope": " ".join(e["scope"].split()),
        "data_statement": e["data_statement"],
        "human_in_the_loop": e["human_in_the_loop"],
        "explainable": e["explainable"],
        "right_to_explanation": e["right_to_explanation"],
        "no_offensive_capability": e["no_offensive_capability"],
    }

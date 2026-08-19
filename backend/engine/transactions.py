"""
Transaction anomaly detection.

Every simulated banking transaction is assessed against the user's OWN history
(personal baseline, not a global rule set) with explainable rules:

    * amount z-score vs the user's mean/std           (unusually large)
    * hard multiple of the user's previous maximum    (way outside envelope)
    * odd-hour transaction (00:00-05:00 NPT)
    * burst: several transactions within a few minutes
    * first transaction after a recent SIM change      (classic drain pattern)

Scores are additive, capped at 100, thresholded by config.yaml ->
transactions.flag_threshold. Flagged transactions raise a dashboard alert and a
(simulated) notification; on a FROZEN account every transaction is refused.
"""
import json
import statistics
from datetime import datetime, timedelta

from . import db, notifier
from .config_loader import load_config


def _history(user_id: int, limit: int = 200) -> list[dict]:
    return db.query_all(
        "SELECT amount, occurred_at FROM transactions WHERE user_id = ? "
        "ORDER BY occurred_at DESC LIMIT ?", (user_id, limit))


def _recent_sim_change(user_id: int, days: int) -> bool:
    cutoff = (datetime.now() - timedelta(days=days)).isoformat(timespec="seconds")
    row = db.query_one(
        "SELECT COUNT(*) AS n FROM sim_events WHERE user_id = ? "
        "AND event_type IN ('sim_swap','imsi_change','iccid_change') AND occurred_at >= ?",
        (user_id, cutoff))
    return (row or {}).get("n", 0) > 0


def assess(user: dict, amount: float, merchant: str = "",
           category: str = "", occurred_at: str | None = None) -> dict:
    """
    Score + record one payment attempt for `user`. Returns the stored record
    with `flagged`, `anomaly_score`, `status` and plain-language `reasons`.

    Statuses: 'posted' (allowed), 'held' (cooling-off hold after a SIM change —
    released only with an out-of-band code), 'refused' (frozen account /
    insufficient funds; not stored).

    SCOPE. SIMShield is not a bank and this is not a payments system. What is
    modelled here is the **containment** control that matters after a SIM swap:
    the first large payment following a SIM change is the drain pattern, so it
    is held rather than allowed or refused, and the release goes through a
    channel the attacker does not hold. `merchant` and `category` are accepted
    only for backward compatibility with existing rows and are no longer
    collected by the UI — knowing what a subscriber buys is not needed to
    detect a SIM swap, so it is not gathered (data minimisation).
    """
    cfg = load_config()["transactions"]
    ts = occurred_at or db.now()

    if user["frozen"]:
        rec = {
            "accepted": False, "status": "refused", "flagged": 1, "anomaly_score": 100.0,
            "reasons": ["Account is frozen — all transactions are refused."],
            "amount": amount, "merchant": merchant, "occurred_at": ts,
        }
        db.log_activity(user["id"], "txn_refused_frozen", {"amount": amount})
        return rec

    balance = user.get("balance", 0.0) or 0.0
    if amount > balance:
        db.log_activity(user["id"], "txn_refused_funds", {"amount": amount})
        return {
            "accepted": False, "status": "refused", "flagged": 0, "anomaly_score": 0.0,
            "reasons": [f"Insufficient funds — available balance is NPR {balance:,.0f}."],
            "amount": amount, "merchant": merchant, "occurred_at": ts,
        }

    hist = _history(user["id"])
    amounts = [h["amount"] for h in hist]
    score, reasons = 0.0, []

    # unusually large vs personal baseline
    if len(amounts) >= cfg["min_history"]:
        mean = statistics.fmean(amounts)
        std = statistics.pstdev(amounts) or max(mean * 0.25, 1.0)
        z = (amount - mean) / std
        if z >= cfg["zscore_flag"]:
            score += 45
            reasons.append(f"Amount is far above your usual spending "
                           f"(≈{z:.1f}σ over your average of NPR {mean:,.0f}).")
        if amounts and amount > max(amounts) * cfg["max_multiple"]:
            score += 25
            reasons.append("Amount exceeds anything previously seen on this account.")

    # odd hour
    try:
        hour = datetime.fromisoformat(ts).hour
    except ValueError:
        hour = 12
    if 0 <= hour < 5:
        score += 15
        reasons.append("Transaction at an unusual hour (00:00–05:00).")

    # burst of transactions
    window_start = (datetime.fromisoformat(ts) - timedelta(
        minutes=cfg["burst_window_min"])).isoformat(timespec="seconds")
    recent = db.query_one(
        "SELECT COUNT(*) AS n FROM transactions WHERE user_id = ? AND occurred_at >= ?",
        (user["id"], window_start))
    if (recent or {}).get("n", 0) >= cfg["burst_count"]:
        score += 20
        reasons.append("Several transactions within a few minutes.")

    # transaction shortly after a SIM change — the classic drain pattern
    recent_swap = _recent_sim_change(user["id"], cfg["sim_change_lookback_days"])
    if recent_swap:
        score += 35
        reasons.append("A SIM change was recorded on this account recently — "
                       "transactions right after a SIM swap are high-risk.")

    score = round(min(score, 100.0), 1)
    flagged = 1 if score >= cfg["flag_threshold"] else 0
    if not reasons:
        reasons.append("Within your normal spending pattern.")

    # Cooling-off hold: a high-value transaction inside the post-SIM-change
    # window is parked instead of posted — funds move only after an email OTP
    # (out-of-band, so a fraudster holding the phone number can't approve it).
    held = recent_swap and amount >= cfg.get("hold_threshold_amount", 10000)
    status = "held" if held else "posted"
    if held:
        reasons.insert(0, f"HELD: transactions over NPR "
                          f"{cfg.get('hold_threshold_amount', 10000):,} are paused for "
                          f"{cfg['sim_change_lookback_days']} days after a SIM change. "
                          "Release it with the code sent to your email.")

    # --- ATOMIC debit + insert (finding F14) ---------------------------------
    # Previously the balance was read in Python, checked, and written back in a
    # separate statement. Two concurrent requests could both read the same
    # balance and both succeed, overdrawing the account. The debit is now a
    # single CONDITIONAL update inside one transaction: `WHERE balance >= ?`
    # means the database itself refuses the second writer, and rowcount tells us
    # which one lost. Simulation only — no real money is involved.
    # NOTE: nothing inside this block may open another database connection.
    # Doing so self-deadlocks — the nested connection waits for the write lock
    # this very transaction is holding. Activity logging happens afterwards.
    lost_race = False
    balance_now = None
    txn_id = None
    with db.db() as con:
        con.execute("BEGIN IMMEDIATE")
        if not held:
            cur = con.execute(
                "UPDATE users SET balance = balance - ? "
                "WHERE id = ? AND balance >= ? AND frozen = 0",
                (amount, user["id"], amount))
            if cur.rowcount != 1:
                # Lost the race, or the account was frozen/overdrawn in between.
                row = con.execute("SELECT balance FROM users WHERE id = ?",
                                  (user["id"],)).fetchone()
                balance_now = row["balance"] if row else 0.0
                lost_race = True
        if not lost_race:
            cur = con.execute(
                "INSERT INTO transactions (user_id, amount, currency, merchant, "
                "category, flagged, anomaly_score, reasons, status, occurred_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (user["id"], amount, "NPR", merchant, category, flagged, score,
                 json.dumps(reasons), status, ts))
            txn_id = cur.lastrowid

    if lost_race:
        db.log_activity(user["id"], "txn_refused_concurrent", {"amount": amount})
        return {"accepted": False, "status": "refused", "flagged": 0,
                "anomaly_score": 0.0, "balance": balance_now,
                "reasons": ["Insufficient funds — another transaction completed "
                            f"first. Available balance is NPR {balance_now:,.0f}."],
                "amount": amount, "merchant": merchant, "occurred_at": ts}

    db.log_activity(user["id"], "transaction",
                    {"amount": amount, "flagged": flagged, "status": status})

    if held:
        notifier.send(
            user, "Transaction held for your protection",
            f"A transaction of NPR {amount:,.0f}" +
            (f" at {merchant}" if merchant else "") +
            " was HELD because your SIM changed recently. Release it from your "
            "dashboard with the emailed code — or, if this was not you, freeze "
            "your account now.",
            alert_type="transaction", severity="critical")
    elif flagged:
        notifier.send(
            user, "Suspicious transaction flagged",
            f"A transaction of NPR {amount:,.0f}" +
            (f" at {merchant}" if merchant else "") +
            f" was flagged (risk {score}/100). {reasons[0]} "
            "If this was not you, freeze your account from the SIMShield dashboard now.",
            alert_type="transaction", severity="critical")

    new_balance = (db.query_one("SELECT balance FROM users WHERE id = ?",
                                (user["id"],)) or {}).get("balance", balance)
    return {"id": txn_id, "accepted": True, "status": status, "flagged": flagged,
            "anomaly_score": score, "reasons": reasons, "balance": new_balance,
            "amount": amount, "merchant": merchant, "occurred_at": ts}


def release_held(user: dict, txn_id: int) -> dict:
    """
    Post a previously-held transaction (the caller must already have verified
    the release OTP).

    ATOMIC AND IDEMPOTENT (finding F15). The old version read the row, checked
    `status == 'held'`, then updated — a check-then-act race in which two
    concurrent releases could both pass the check and debit the balance twice.
    The status transition is now a conditional update guarded by
    `WHERE status = 'held'`, so exactly one caller can win; the loser is told
    the transaction was already released rather than silently double-spending.
    """
    # As above: no nested connections inside the transaction.
    with db.db() as con:
        con.execute("BEGIN IMMEDIATE")
        txn = con.execute(
            "SELECT * FROM transactions WHERE id = ? AND user_id = ?",
            (txn_id, user["id"])).fetchone()
        if txn is None:
            raise ValueError("No transaction with that ID.")
        if txn["status"] != "held":
            raise ValueError(f"This transaction is already {txn['status']}.")

        # Claim the transition first; only the winner proceeds to debit.
        claimed = con.execute(
            "UPDATE transactions SET status = 'released' "
            "WHERE id = ? AND status = 'held'", (txn_id,)).rowcount
        if claimed != 1:
            raise ValueError("This transaction has already been released.")

        debited = con.execute(
            "UPDATE users SET balance = balance - ? "
            "WHERE id = ? AND balance >= ? AND frozen = 0",
            (txn["amount"], user["id"], txn["amount"])).rowcount
        if debited != 1:
            # Roll the status back so the hold can be retried after a top-up.
            con.execute("UPDATE transactions SET status = 'held' WHERE id = ?",
                        (txn_id,))
            raise ValueError("Insufficient funds to release this transaction.")
        balance = con.execute("SELECT balance FROM users WHERE id = ?",
                              (user["id"],)).fetchone()["balance"]
        amount = txn["amount"]

    db.log_activity(user["id"], "txn_released",
                    {"txn_id": txn_id, "amount": amount})
    return {"ok": True, "txn_id": txn_id, "balance": balance}


def list_for_user(user_id: int, limit: int = 25) -> list[dict]:
    rows = db.query_all(
        "SELECT * FROM transactions WHERE user_id = ? ORDER BY occurred_at DESC LIMIT ?",
        (user_id, limit))
    for r in rows:
        r["reasons"] = json.loads(r["reasons"] or "[]")
    return rows

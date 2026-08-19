"""
Seed the SIMShield database with demo accounts and realistic synthetic history.

    python seed_demo.py            # creates data/simshield.db content
    python seed_demo.py --reset    # wipe the DB first, then seed

Accounts created (all SYNTHETIC):

    aarav@example.np  / Demo@1234   user   linked to profile aarav_safe
    gita@example.np   / Demo@1234   user   linked to profile gita_newsim (recent SIM change)
    fraud@simshield.np / Admin@1234 admin  fraud-team dashboard

Aarav gets a healthy history (transactions, logins); Gita gets the risky one
(SIM swap event, flagged transaction, escalation) so both ends of the risk
spectrum are demonstrable immediately after seeding.
"""
import json
import os
import random
import sys
from datetime import datetime, timedelta

from engine import auth, db, privacy, transactions
from engine.config_loader import backend_path

random.seed(42)


def iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def wipe():
    path = db.DB_PATH
    for suffix in ("", "-wal", "-shm"):
        p = path + suffix
        if os.path.exists(p):
            os.remove(p)
    print(f"Removed {path}")


def seed_user(email, password, name, phone, operator, profile_id, role="user",
              trusted_contact="", balance=150000.0):
    if auth.get_user_by_email(email):
        print(f"  {email} already exists — skipping")
        return auth.get_user_by_email(email)
    u = auth.register(email=email, password=password, display_name=name,
                      phone=phone, operator=operator, profile_id=profile_id,
                      role=role, trusted_contact=trusted_contact, balance=balance)
    print(f"  created {role}: {email}")
    return u


def backfill_transactions(user, days=45, per_week=5, base=2500.0):
    """Insert a personal spending baseline directly (no anomaly assessment —
    history is assumed reviewed; only NEW transactions get scored)."""
    merchants = [("Bhatbhateni Supermarket", "groceries"), ("NTC Topup", "telecom"),
                 ("Himalayan Java", "food"), ("Sajha Yatayat", "transport"),
                 ("Daraz", "shopping"), ("NEA Bill", "utilities")]
    n = int(days / 7 * per_week)
    for i in range(n):
        when = datetime.now() - timedelta(days=random.uniform(1, days),
                                          hours=random.uniform(0, 12))
        merchant, cat = random.choice(merchants)
        amount = round(max(80.0, random.gauss(base, base * 0.35)), 0)
        db.execute(
            "INSERT INTO transactions (user_id, amount, currency, merchant, category, "
            "flagged, anomaly_score, reasons, occurred_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (user["id"], amount, "NPR", merchant, cat, 0, 0.0,
             json.dumps(["Within your normal spending pattern."]), iso(when)))


def backfill_logins(user, days=30):
    """Give the sequence model a login history (regular daytime pattern)."""
    for d in range(days, 0, -2):
        when = datetime.now() - timedelta(days=d, hours=random.choice([-2, 0, 1, 3]))
        db.execute(
            "INSERT INTO activity_log (user_id, action, meta, created_at) VALUES (?,?,?,?)",
            (user["id"], "login_ok", json.dumps({"device_known": True}), iso(when)))


def main():
    if "--reset" in sys.argv:
        wipe()
    db.init_db()
    print("Seeding demo data (all synthetic)…")

    aarav = seed_user("aarav@example.np", "Demo@1234", "Aarav Sharma",
                      "+977-9841002200", "NTC", "aarav_safe",
                      trusted_contact="sunita.sharma@example.np", balance=184500.0)
    gita = seed_user("gita@example.np", "Demo@1234", "Gita Rai",
                     "+977-9801234567", "NCELL", "gita_newsim",
                     trusted_contact="binod.rai@example.np", balance=96200.0)
    seed_user("fraud@simshield.np", "Admin@1234", "Fraud Desk (Kathmandu)",
              "+977-9851000000", "NTC", None, role="admin", balance=0.0)

    # Aarav manages his own geo-fence (feeds the pre-OTP location check)
    db.execute("UPDATE users SET safe_zones = ? WHERE id = ?",
               (json.dumps([
                   {"name": "Home — Thamel, Kathmandu", "lat": 27.7154, "lon": 85.3123},
                   {"name": "Office — Durbar Marg", "lat": 27.7130, "lon": 85.3160},
               ]), aarav["id"]))

    # a little risk-history so the dashboard sparkline has a story to tell
    for user, series in ((aarav, [8, 6, 12, 6, 5]), (gita, [10, 12, 35, 62, 71])):
        for d, score in enumerate(series):
            level = ("LOW" if score < 20 else "GUARDED" if score < 45
                     else "ELEVATED" if score < 70 else "HIGH")
            db.execute("INSERT INTO risk_history (user_id, score, level, created_at) "
                       "VALUES (?,?,?,?)",
                       (user["id"], float(score), level,
                        iso(datetime.now() - timedelta(days=len(series) - d))))

    # --- Aarav: healthy account ---------------------------------------------
    backfill_transactions(aarav, base=2500.0)
    backfill_logins(aarav)
    db.execute("INSERT INTO sim_events (user_id, event_type, operator, imsi_hash, "
               "imei_hash, risk_score, details, occurred_at) VALUES (?,?,?,?,?,?,?,?)",
               (aarav["id"], "sim_activated", "NTC", privacy.hash_id("imsi-aarav"),
                privacy.hash_id("356938035643809"), 5.0,
                "Original SIM activation (2019)", "2019-04-12T10:00:00"))

    # --- Gita: the at-risk account -------------------------------------------
    backfill_transactions(gita, base=1800.0)
    backfill_logins(gita, days=20)
    two_weeks = iso(datetime.now() - timedelta(days=14))
    five_days = iso(datetime.now() - timedelta(days=5))
    db.execute("INSERT INTO sim_events (user_id, event_type, operator, imsi_hash, "
               "imei_hash, risk_score, details, occurred_at) VALUES (?,?,?,?,?,?,?,?)",
               (gita["id"], "sim_activated", "NCELL", privacy.hash_id("imsi-gita-1"),
                privacy.hash_id("351234567890123"), 10.0,
                "SIM re-registration at operator store", two_weeks))
    db.execute("INSERT INTO sim_events (user_id, event_type, operator, imsi_hash, "
               "imei_hash, risk_score, details, occurred_at) VALUES (?,?,?,?,?,?,?,?)",
               (gita["id"], "sim_swap", "NCELL", privacy.hash_id("imsi-gita-2"),
                privacy.hash_id("990001234567899"), 88.0,
                "Number moved to a new SIM via agent channel", five_days))
    db.add_alert(gita["id"], "sim_swap",
                 "Your number was moved to a different SIM card 5 days ago. If you "
                 "did not request this, freeze your account and call Ncell (9005).",
                 severity="critical",
                 meta={"reasons": ["SIM activated 5 days ago",
                                   "IMSI changed on the network"]})
    # a genuinely-scored suspicious transaction on top of her baseline
    fresh_gita = auth.get_user(gita["id"])
    result = transactions.assess(fresh_gita, 48500.0, merchant="Unknown online merchant",
                                 category="transfer")
    print(f"  Gita demo transaction flagged={bool(result['flagged'])} "
          f"score={result['anomaly_score']}")

    print("\nDone. Demo credentials:")
    print("  user : aarav@example.np  / Demo@1234   (healthy account)")
    print("  user : gita@example.np   / Demo@1234   (recent SIM swap, alerts)")
    print("  admin: fraud@simshield.np / Admin@1234  (fraud-team dashboard)")


if __name__ == "__main__":
    main()

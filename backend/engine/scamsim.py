"""
'Spot the scam' trainer — gamified awareness through realistic (synthetic)
message examples localised to Nepal.

The user is shown a message and guesses scam / legitimate; the server checks
the answer and returns the explanation, so answers never ship to the client.
Rounds are scored and feed the gamification system. All sender names, numbers
and links are fabricated for training.
"""
import random

ITEMS = [
    {"id": "otp_share", "scam": True,
     "text": "NTC Alert: Your SIM will be BLOCKED in 24 hrs. To keep your number "
             "active, reply with the 6-digit code we just sent you.",
     "explain": "No operator ever asks you to send back an OTP. Asking for a code "
                "you just received is the signature move of a SIM-swap attacker."},
    {"id": "bank_link", "scam": True,
     "text": "Dear customer, your mobile banking is suspended. Re-activate now: "
             "http://nabil-bank-verify.xyz/login",
     "explain": "Banks don't send login links on odd domains ('.xyz', misspelled "
                "names). Always type your bank's address yourself."},
    {"id": "real_otp", "scam": False,
     "text": "Your OTP for login is 493022. Valid for 5 minutes. NEVER share this "
             "code with anyone, including bank staff.",
     "explain": "A normal OTP delivery: it tells you the code and warns you not to "
                "share it. It becomes dangerous only if someone asks you for it."},
    {"id": "khalti_prize", "scam": True,
     "text": "Congratulations! Your number won NPR 25,00,000 in the Khalti Dashain "
             "lottery. Send NPR 5,000 processing fee to claim.",
     "explain": "Advance-fee fraud: real prizes never require you to pay first, and "
                "you can't win a lottery you never entered."},
    {"id": "real_txn_alert", "scam": False,
     "text": "NPR 2,450.00 debited from A/C ***2201 at Bhatbhateni on 12-Jul. "
             "Not you? Call 01-4227181 (number on the back of your card).",
     "explain": "A legitimate transaction alert: masked account, no links, and it "
                "points you to the official number you can verify independently."},
    {"id": "kyc_urgent", "scam": True,
     "text": "eSewa KYC EXPIRED!! Account will be deleted TODAY. Update immediately "
             "by calling 98XXXXXXXX and sharing your MPIN.",
     "explain": "Urgency + a personal mobile number + asking for your MPIN: wallet "
                "providers never ask for PINs, and KYC is updated in-app only."},
    {"id": "sim_upgrade", "scam": True,
     "text": "Ncell 4G Dept: We are upgrading your SIM to 5G remotely. Tell us the "
             "19-digit number printed on your SIM card to activate.",
     "explain": "The 19-digit ICCID identifies your physical SIM — with it, an "
                "attacker can social-engineer a swap. Upgrades happen in stores."},
    {"id": "real_maintenance", "scam": False,
     "text": "Nepal Telecom: network maintenance in Lalitpur on Saturday 2-4 AM. "
             "Voice/SMS may be briefly unavailable. No action is needed.",
     "explain": "Informational, asks for nothing, requires no action, no links — "
                "consistent with a genuine service broadcast."},
]

_BY_ID = {i["id"]: i for i in ITEMS}


def quiz(n: int = 5) -> list[dict]:
    """A randomized round WITHOUT answers (they stay server-side)."""
    picked = random.sample(ITEMS, k=min(n, len(ITEMS)))
    return [{"id": i["id"], "text": i["text"]} for i in picked]


def check(item_id: str, guess_scam: bool) -> dict | None:
    item = _BY_ID.get(item_id)
    if item is None:
        return None
    return {"correct": bool(guess_scam) == item["scam"],
            "is_scam": item["scam"], "explain": item["explain"]}

"""
Built-in demo scenarios (shared by the detection page and the evaluation harness).

Each scenario pairs a synthetic profile with a login attempt and the decision we
expect the fused engine to reach. They double as an end-to-end regression suite
(see evaluate.py -> scenario_metrics) and as the demo catalogue on /detection.

There are ten scenarios for each of the four decisions — ALLOW, MONITOR, VERIFY
and BLOCK — so the suite exercises the boundaries between classes rather than
only the easy extremes.

All data is synthetic. Attempt timestamps and profile ages are RELATIVE to now:
both used to be pinned to a "demo today" of 2026-07-05, which made the fixtures
decay silently — weeks later a SIM authored as "1 day old" scored as 39 days old
and the BLOCK case quietly became VERIFY while still looking correct.
"""
from datetime import datetime, timedelta

from engine.profiles import load as _profile


def _at(hour: int, minute: int = 0, days_ago: int = 0) -> str:
    """A local timestamp today (or `days_ago` days back) at the given time."""
    now = datetime.now()
    t = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if days_ago == 0 and t > now:
        t -= timedelta(days=1)
    return (t - timedelta(days=days_ago)).isoformat(timespec="seconds")


# --- Locations (real public landmarks used purely as synthetic points) --------
KTM_HOME = {"lat": 27.7154, "lon": 85.3123}      # Thamel
PATAN = {"lat": 27.6766, "lon": 85.3250}
BHAKTAPUR = {"lat": 27.6722, "lon": 85.4298}
KIRTIPUR = {"lat": 27.6786, "lon": 85.2770}
NEWROAD = {"lat": 27.7017, "lon": 85.3106}
BOUDHA = {"lat": 27.7215, "lon": 85.3620}
KALANKI = {"lat": 27.6933, "lon": 85.2816}
PULCHOWK = {"lat": 27.6795, "lon": 85.3168}
CHITWAN = {"lat": 27.5291, "lon": 84.3542}       # ~90 km
POKHARA = {"lat": 28.2096, "lon": 83.9588}       # ~140 km
BIRATNAGAR = {"lat": 26.4525, "lon": 87.2718}    # ~330 km
DELHI = {"lat": 28.6139, "lon": 77.2090}         # ~800 km
DOHA = {"lat": 25.2854, "lon": 51.5310}          # ~3,400 km
LAGOS = {"lat": 6.5244, "lon": 3.3792}           # ~9,000 km
MOSCOW = {"lat": 55.7558, "lon": 37.6173}        # ~4,900 km


def S(name, user, attempt, expect, note=""):
    return {"name": name, "profile": _profile(user), "attempt": attempt,
            "expected_decision": expect, "note": note}


# =============================================================================
# ALLOW — established SIM, known device, at or near a safe zone
# =============================================================================
ALLOW = [
    S("Morning login at home", "aarav_safe",
      {"current_location": KTM_HOME, "imei": "356938035643809", "timestamp": _at(9, 0),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "ALLOW", "The everyday case: nothing unusual anywhere."),
    S("Lunchtime balance check", "ramesh_lowrisk",
      {"current_location": KIRTIPUR, "imei": "353112223334445", "timestamp": _at(13, 15),
       "logins_last_24h": 2, "failed_logins_last_24h": 0},
      "ALLOW", "Repeat login same day is normal behaviour."),
    S("Student on campus", "anita_student",
      {"current_location": KIRTIPUR, "imei": "354820061122334", "timestamp": _at(11, 30),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "ALLOW", "Long-established Smart Cell SIM at a registered zone."),
    S("Pensioner, same phone for years", "suresh_elderly",
      {"current_location": BOUDHA, "imei": "356701099887766", "timestamp": _at(10, 0),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "ALLOW", "Seven-year-old SIM, single device, never travels."),
    S("Business owner at the office", "deepak_business",
      {"current_location": NEWROAD, "imei": "357004455667788", "timestamp": _at(15, 0),
       "logins_last_24h": 3, "failed_logins_last_24h": 0},
      "ALLOW", "Multiple daily logins are this user's norm."),
    S("Second registered handset", "rekha_dual",
      {"current_location": KALANKI, "imei": "354911223344567", "timestamp": _at(19, 20),
       "logins_last_24h": 2, "failed_logins_last_24h": 0},
      "ALLOW", "A second device is fine when it is already registered."),
    S("Evening login, one typo", "aarav_safe",
      {"current_location": KTM_HOME, "imei": "356938035643809", "timestamp": _at(20, 40),
       "logins_last_24h": 2, "failed_logins_last_24h": 1},
      "ALLOW", "A single mistyped password should not punish anyone."),
    S("Working from the Lalitpur office", "deepak_business",
      {"current_location": PULCHOWK, "imei": "357004455667799", "timestamp": _at(12, 10),
       "logins_last_24h": 2, "failed_logins_last_24h": 0},
      "ALLOW", "Second registered zone, second registered device."),
    S("Short hop across the valley", "rekha_dual",
      {"current_location": KIRTIPUR, "imei": "354911223344556", "timestamp": _at(17, 5),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "ALLOW", "Movement inside the Kathmandu Valley is routine."),
    S("New customer, settled account", "kabita_newuser",
      {"current_location": PULCHOWK, "imei": "351009988776655", "timestamp": _at(14, 45),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "ALLOW", "A two-month-old SIM is past the risky window."),
]

# =============================================================================
# MONITOR — genuine but atypical: distance, hours, or mild device novelty
# =============================================================================
MONITOR = [
    S("Traveller in Pokhara", "bibek_traveler",
      {"current_location": POKHARA, "imei": "357921035123456", "timestamp": _at(11, 0),
       "logins_last_24h": 2, "failed_logins_last_24h": 0},
      "MONITOR", "140 km away, but everything else checks out."),
    S("Weekend trip to Chitwan", "aarav_safe",
      {"current_location": CHITWAN, "imei": "356938035643809", "timestamp": _at(16, 30),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "MONITOR", "Distance alone should flag, not block."),
    S("Family visit in Biratnagar", "anita_student",
      {"current_location": BIRATNAGAR, "imei": "354820061122334", "timestamp": _at(18, 0),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "MONITOR", "330 km with an established SIM and known phone."),
    S("Overnight bus, checking balance", "bibek_traveler",
      {"current_location": POKHARA, "imei": "357921035123456", "timestamp": _at(2, 40),
       "logins_last_24h": 2, "failed_logins_last_24h": 0},
      "MONITOR", "Distance and an odd hour together — two mild signals, no identity change."),
    S("Migrant worker in Doha", "bikash_migrant",
      {"current_location": DOHA, "imei": "356220011223344", "timestamp": _at(7, 45),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "MONITOR", "Abroad is normal for this user; SIM and device are old."),
    S("Business trip to Delhi", "deepak_business",
      {"current_location": DELHI, "imei": "357004455667788", "timestamp": _at(9, 30),
       "logins_last_24h": 2, "failed_logins_last_24h": 0},
      "MONITOR", "Cross-border, but a five-year-old SIM and known handset."),
    S("Pensioner locked out at dawn", "suresh_elderly",
      {"current_location": BOUDHA, "imei": "356701099887766", "timestamp": _at(4, 50),
       "logins_last_24h": 4, "failed_logins_last_24h": 3},
      "MONITOR", "Odd hour plus a run of failures — note it, but it's their own "
                 "home and handset. Contrast with the VERIFY case where the same "
                 "pattern happens on a device never seen before."),
    S("Abroad on a new network", "bikash_migrant",
      {"current_location": DOHA, "imei": "356220011223344", "timestamp": _at(23, 30),
       "logins_last_24h": 3, "failed_logins_last_24h": 1, "ip_change_flag": 1},
      "MONITOR", "Far away with an IP change — expected for a migrant worker."),
    S("Holiday in Pokhara, new IP", "nabin_newphone",
      {"current_location": POKHARA, "imei": "356551122334455", "timestamp": _at(13, 40),
       "logins_last_24h": 1, "failed_logins_last_24h": 0, "ip_change_flag": 1},
      "MONITOR", "Hotel wifi changes the IP — expected while travelling."),
    S("New customer travelling", "kabita_newuser",
      {"current_location": CHITWAN, "imei": "351009988776655", "timestamp": _at(8, 50),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "MONITOR", "Younger account plus distance stacks two mild signals."),
]

# =============================================================================
# VERIFY — real suspicion: recent SIM, new device, or several stacked flags.
# Step up authentication; never auto-punish.
# =============================================================================
VERIFY = [
    S("New SIM and new phone", "gita_newsim",
      {"current_location": BHAKTAPUR, "imei": "351234567890999", "timestamp": _at(10, 30),
       "logins_last_24h": 2, "failed_logins_last_24h": 1,
       "iccid_change_flag": 1, "otp_sim_gap_minutes": 90},
      "VERIFY", "The classic ambiguous case — could be a genuine upgrade."),
    S("SIM reissued after losing a phone", "pratima_reissue",
      {"current_location": PATAN, "imei": "351778899001122", "timestamp": _at(12, 0),
       "logins_last_24h": 1, "failed_logins_last_24h": 0, "iccid_change_flag": 1},
      "VERIFY", "Legitimate reissue still deserves a step-up check."),
    S("Recent SIM, unknown handset", "gita_newsim",
      {"current_location": BHAKTAPUR, "imei": "999888777666555", "timestamp": _at(21, 10),
       "logins_last_24h": 3, "failed_logins_last_24h": 1},
      "VERIFY", "Fresh SIM plus a device never seen before."),
    S("Reissued SIM, out of town", "pratima_reissue",
      {"current_location": POKHARA, "imei": "351778899001122", "timestamp": _at(15, 30),
       "logins_last_24h": 2, "failed_logins_last_24h": 0, "ip_change_flag": 1},
      "VERIFY", "Recent SIM and distance together raise the bar."),
    S("New phone, established SIM", "nabin_newphone",
      {"current_location": BHAKTAPUR, "imei": "111222333444555", "timestamp": _at(11, 15),
       "logins_last_24h": 2, "failed_logins_last_24h": 2, "ip_change_flag": 1},
      "VERIFY", "Device change plus failed attempts — verify before proceeding."),
    S("Odd hour on an unknown device", "anita_student",
      {"current_location": KIRTIPUR, "imei": "888777666555444", "timestamp": _at(3, 20),
       "logins_last_24h": 4, "failed_logins_last_24h": 2},
      "VERIFY", "Night-time, new device, repeated attempts."),
    S("New SIM abroad, otherwise clean", "gita_newsim",
      {"current_location": DELHI, "imei": "351234567890123", "timestamp": _at(14, 0),
       "logins_last_24h": 1, "failed_logins_last_24h": 0},
      "VERIFY", "Recent SIM plus 800 km, but the registered handset."),
    S("New customer, new device, far away", "kabita_newuser",
      {"current_location": BIRATNAGAR, "imei": "222333444555666", "timestamp": _at(22, 30),
       "logins_last_24h": 3, "failed_logins_last_24h": 1},
      "VERIFY", "Three mild signals stacking into real suspicion."),
    S("Session used from another country", "rekha_dual",
      {"current_location": KALANKI, "imei": "354911223344556", "timestamp": _at(1, 40),
       "logins_last_24h": 7, "failed_logins_last_24h": 4,
       # SIM is where it should be; the *login* is the thing out of place.
       "sim_network_area": "Kalanki"},
      "VERIFY", "Burst of failures overnight looks like credential stuffing — "
                "the SIM is still at home, so this is a stolen password, not a swap."),
    S("Physical SIM converted to eSIM", "pratima_reissue",
      {"current_location": NEWROAD, "imei": "351778899001122", "timestamp": _at(16, 45),
       "logins_last_24h": 3, "failed_logins_last_24h": 1,
       "sim_type_change_flag": 1, "ip_change_flag": 1, "otp_sim_gap_minutes": 12},
      "VERIFY", "eSIM conversion is the modern swap vector — verify, don't assume."),
]

# =============================================================================
# BLOCK — the SIM-swap fingerprint: SIM activated within days, identity changes
# on the network, unknown device, far from home, OTP requested immediately.
# No OTP is ever issued for these.
# =============================================================================
BLOCK = [
    S("SIM-swap fraud, abroad", "sita_swapped",
      {"current_location": DELHI, "imei": "868999777666555", "timestamp": _at(8, 15),
       "logins_last_24h": 6, "failed_logins_last_24h": 3,
       "imsi_change_flag": 1, "iccid_change_flag": 1, "ip_change_flag": 1,
       "otp_sim_gap_minutes": 4},
      "BLOCK", "Textbook attack: 1-day SIM, identity changed, 800 km away."),
    S("Swapped today, draining fast", "manish_swapped",
      {"current_location": KTM_HOME, "imei": "777666555444333", "timestamp": _at(2, 30),
       "logins_last_24h": 9, "failed_logins_last_24h": 4,
       "imsi_change_flag": 1, "iccid_change_flag": 1, "otp_sim_gap_minutes": 2},
      "BLOCK", "Same city is no defence when the SIM changed hours ago."),
    S("Targeted victim, second attempt", "binita_targeted",
      {"current_location": MOSCOW, "imei": "666555444333222", "timestamp": _at(4, 5),
       "logins_last_24h": 8, "failed_logins_last_24h": 5,
       "imsi_change_flag": 1, "iccid_change_flag": 1, "ip_change_flag": 1,
       "otp_sim_gap_minutes": 3},
      "BLOCK", "Two swaps in 30 days and a login from 4,900 km away."),
    S("Fresh SIM, unknown continent", "manish_swapped",
      {"current_location": LAGOS, "imei": "555444333222111", "timestamp": _at(3, 15),
       "logins_last_24h": 5, "failed_logins_last_24h": 2,
       "imsi_change_flag": 1, "ip_change_flag": 1, "otp_sim_gap_minutes": 6},
      "BLOCK", "Impossible travel plus a same-day SIM activation."),
    S("Immediate OTP after SIM change", "sita_swapped",
      {"current_location": PATAN, "imei": "444333222111000", "timestamp": _at(1, 10),
       "logins_last_24h": 7, "failed_logins_last_24h": 3,
       "imsi_change_flag": 1, "iccid_change_flag": 1, "otp_sim_gap_minutes": 1},
      "BLOCK", "A one-minute gap between SIM change and OTP is decisive."),
    S("Spoofed location, SIM says otherwise", "binita_targeted",
      {"current_location": PATAN, "imei": "333222111000999", "timestamp": _at(3, 50),
       "logins_last_24h": 6, "failed_logins_last_24h": 4,
       "imsi_change_flag": 1, "iccid_change_flag": 1, "sim_type_change_flag": 1,
       "otp_sim_gap_minutes": 2,
       # Operator feed places the SIM on a Delhi tower while the login claims
       # Patan — the mismatch signal that GPS spoofing cannot defeat.
       "sim_network_area": "Delhi"},
      "BLOCK", "The login claims Patan; the network says the SIM is in Delhi. "
               "A phone and its SIM travel together, so this cannot be the owner."),
    S("eSIM hijack, cross-border", "manish_swapped",
      {"current_location": DELHI, "imei": "222111000999888", "timestamp": _at(5, 25),
       "logins_last_24h": 6, "failed_logins_last_24h": 3,
       "imsi_change_flag": 1, "sim_type_change_flag": 1, "ip_change_flag": 1,
       "otp_sim_gap_minutes": 5},
      "BLOCK", "Physical SIM converted to eSIM by the attacker."),
    S("Rapid retries after the swap", "sita_swapped",
      {"current_location": DOHA, "imei": "111000999888777", "timestamp": _at(0, 45),
       "logins_last_24h": 12, "failed_logins_last_24h": 7,
       "imsi_change_flag": 1, "iccid_change_flag": 1, "ip_change_flag": 1,
       "otp_sim_gap_minutes": 3},
      "BLOCK", "Twelve attempts overnight from 3,400 km away."),
    S("Serial swapper, new device", "binita_targeted",
      {"current_location": BIRATNAGAR, "imei": "000999888777666", "timestamp": _at(2, 55),
       "logins_last_24h": 7, "failed_logins_last_24h": 4,
       "imsi_change_flag": 1, "iccid_change_flag": 1, "ip_change_flag": 1,
       "otp_sim_gap_minutes": 4},
      "BLOCK", "Repeat SIM changes are the strongest historical signal."),
    S("Swapped SIM, dead of night, abroad", "manish_swapped",
      {"current_location": MOSCOW, "imei": "999000111222333", "timestamp": _at(3, 5),
       "logins_last_24h": 10, "failed_logins_last_24h": 6,
       "imsi_change_flag": 1, "iccid_change_flag": 1, "ip_change_flag": 1,
       "sim_type_change_flag": 1, "otp_sim_gap_minutes": 1},
      "BLOCK", "Every signal the engine has, firing at once."),
]

SCENARIOS = ALLOW + MONITOR + VERIFY + BLOCK

# Grouped view for the detection page's picker.
SCENARIO_GROUPS = [
    {"decision": "ALLOW", "label": "Normal, low-risk logins", "scenarios": ALLOW},
    {"decision": "MONITOR", "label": "Genuine but unusual", "scenarios": MONITOR},
    {"decision": "VERIFY", "label": "Suspicious — step up authentication", "scenarios": VERIFY},
    {"decision": "BLOCK", "label": "SIM-swap fingerprint — refuse before OTP", "scenarios": BLOCK},
]

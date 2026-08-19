"""
Mobile-operator integration — SIMULATED. Facade over the adapter boundary.

This module is the only thing the rest of SIMShield calls to obtain operator
data. It resolves consent, invokes the configured adapter through `safe_call`,
audits the access, and converts the typed `OperatorResult` into the shape the
detection engine expects.

WHY A FACADE RATHER THAN CALLING THE ADAPTER DIRECTLY
The fail-open guarantee has to live in exactly one place, or it does not exist.
`location_mismatch` below computes `mismatch` INSIDE the `if result.usable`
branch and returns a hard `False` on every other path — so an outage, a timeout,
a stale reading, a rate-limit, a malformed payload, disagreeing sources or a
withdrawn consent all produce identically zero risk contribution. There is no
config key that can change this and no branch that adds points when data is
missing. `tests/test_operator_adapter.py::TestFailOpen` proves it for all nine
modes, and `evaluate_operator.py` measures it over the whole scenario suite.

WHAT OPERATOR DATA IS FOR
Comparing where the SIM *is* against where the login *claims* to be catches a
case SIM-recency alone misses: an attacker who spoofs GPS or uses a VPN to look
like they are at the victim's home. A phone and its SIM travel together, so a
genuine traveller shows no mismatch — but someone signing in from Kathmandu
while the SIM sits on a Delhi tower is not the account holder.

Neither a bank nor an app can obtain this directly: the operator holds the
VLR/HLR records. Nothing on the subscriber's handset can answer it either —
after a swap the number lives in the attacker's phone while the victim's app is
still on the victim's phone, so device GPS reports the wrong person entirely.
That is why the boundary is an operator API, and why this project simulates it:
see `engine/operator_camara.py` for what a real integration would require.

Every value produced here is synthetic.
"""
from __future__ import annotations

from . import compliance
from .operator_adapter import (ConsentState, OperatorStatus, get_adapter,
                               operator_config, safe_call)

# Operator contact numbers surfaced to users in alerts and the playbook.
OPERATORS = {
    "NTC": {"name": "Nepal Telecom", "care": "1498"},
    "NCELL": {"name": "Ncell Axiata", "care": "9005"},
    "SMART": {"name": "Smart Cell", "care": "4242"},
}


def _subject(profile: dict | None, attempt: dict | None = None) -> dict:
    """
    The adapter's view of who is being asked about.

    Only an opaque profile id crosses the boundary — never a phone number,
    IMSI or ICCID, none of which the adapter needs to do its job.
    """
    profile = profile or {}
    return {"id": profile.get("user_id") or "anonymous",
            "profile": profile, "attempt": attempt or {}}


def _call(operation: str, profile: dict | None, attempt: dict | None, **kwargs):
    """Resolve consent, call the adapter safely, audit the access."""
    consent = compliance.operator_consent_state(profile, attempt)
    subject = _subject(profile, attempt)
    result = safe_call(get_adapter(), operation, subject, consent, **kwargs)
    # Audit every access, including the ones that returned nothing.
    try:
        compliance.record_operator_access(subject["id"], result)
    except Exception:                              # noqa: BLE001
        # Auditing must never be able to break a login. A failure here is a
        # logging problem, not an authorisation one.
        pass
    return result


# --- location -----------------------------------------------------------------
def get_sim_location(profile: dict, attempt: dict | None = None,
                     fallback: dict | None = None) -> dict | None:
    """
    Where the operator says this SIM is, already coarsened to an area.

    Returns None when there is nothing to report at all. Otherwise the dict
    always carries `status`, `usable`, `source` and `simulated`, so a caller
    cannot mistake a device assumption for a network reading — that distinction
    used to be a bare `source` string and is now a typed status.

    There is deliberately no lat/lon in the return value: operator-derived
    coordinates are never constructed (see `engine/operator_mock.py`).
    """
    claimed = None
    if attempt and (attempt.get("current_location") or {}).get("lat") is not None:
        claimed = attempt["current_location"]
    elif fallback and fallback.get("lat") is not None:
        claimed = fallback

    result = _call("sim_location", profile, attempt, claimed=claimed)
    if result.data is None:
        return {"status": result.status.value, "usable": False,
                "area": None, "country": None, "cell_id": None,
                "distance_km": None, "distance_band": "unknown",
                "origin": None, "source": result.source,
                "degraded_reason": result.degraded_reason,
                "retrieved_at": result.retrieved_at,
                "explain": result.explain(), "simulated": result.simulated}
    d = result.data
    return {
        "status": result.status.value,
        "usable": result.usable,
        "area": d.area, "country": d.country, "cell_id": d.cell_id,
        "distance_km": d.distance_km, "distance_band": d.distance_band,
        "origin": d.origin,
        "source": result.source,
        "fresh": result.fresh, "age_seconds": result.age_seconds,
        "latency_ms": round(result.latency_ms, 1),
        "consent": result.consent.value,
        "degraded_reason": result.degraded_reason,
        "retrieved_at": result.retrieved_at,
        "explain": result.explain(),
        "simulated": result.simulated,
    }


def location_mismatch(profile: dict, attempt: dict,
                      threshold_km: float | None = None) -> dict:
    """
    Compare the network-reported SIM area against the location the login claims.

    Returns {available, km, mismatch, sim_area, claimed_area, cell_id, status,
             explain}. `mismatch` is the ONLY field that can add risk, and it is
    computed inside the usable branch below — every degraded path returns the
    zero-risk dict unchanged.
    """
    if threshold_km is None:
        threshold_km = operator_config()["mismatch_km"]

    claimed = attempt.get("current_location") or {}
    result = _call("sim_location", profile, attempt,
                   claimed=claimed if claimed.get("lat") is not None else None)

    # The fail-open baseline. Every field that could raise a score is falsy,
    # and this object is what is returned for eight of the nine degradation
    # modes — the ninth (ASSUMED_COLOCATED) also lands here because an
    # assumption is not evidence.
    out = {"available": False, "km": None, "mismatch": False,
           "sim_area": None, "claimed_area": None, "cell_id": None,
           "status": result.status.value,
           "degraded_reason": result.degraded_reason,
           "explain": result.explain()}

    if not result.usable or result.data is None:
        return out
    if result.data.origin != "operator_feed" or result.data.distance_km is None:
        return out

    from . import geo
    km = result.data.distance_km
    out.update({
        "available": True,
        "km": round(km, 1),
        "mismatch": bool(km >= float(threshold_km)),
        "sim_area": result.data.area,
        "claimed_area": geo.nearest_place(claimed["lat"], claimed["lon"])["place"],
        "cell_id": result.data.cell_id,
        "distance_band": result.data.distance_band,
    })
    return out


# --- SIM swap -----------------------------------------------------------------
def sim_swap_check(profile: dict, max_age_days: int = 7,
                   attempt: dict | None = None) -> dict:
    """
    The CAMARA `sim-swap/check` equivalent: has this number's SIM changed
    within `max_age_days`? In production this is authoritative operator data;
    here it is derived from the synthetic profile.

    On any degraded status the answer is `swapped: None` — explicitly unknown,
    never `False`. Reporting "no swap" when the operator could not be reached
    would be a false reassurance to the subscriber and a false negative to the
    engine, which is the fail-open error worth avoiding.
    """
    result = _call("sim_swap_check", profile, attempt, max_age_days=max_age_days)
    base = {
        "status": result.status.value, "usable": result.usable,
        "source": result.source, "consent": result.consent.value,
        "fresh": result.fresh, "latency_ms": round(result.latency_ms, 1),
        "checked_at": result.retrieved_at,
        "degraded_reason": result.degraded_reason,
        "explain": result.explain(), "simulated": result.simulated,
    }
    if not result.usable or result.data is None:
        return {**base, "swapped": None, "sim_age_days": None,
                "max_age_days": max_age_days, "operator": (profile or {}).get("operator")}
    d = result.data
    return {**base, "swapped": d.swapped, "sim_age_days": d.sim_age_days,
            "max_age_days": d.max_age_days, "operator": d.operator}


def health() -> dict:
    """Adapter identity and posture, for the admin page and the model card."""
    adapter = get_adapter()
    cfg = operator_config()
    return {
        "adapter": adapter.name,
        "implemented": getattr(adapter, "implemented", True),
        "simulated": adapter.simulated,
        "timeout_ms": cfg["timeout_ms"],
        "max_age_seconds": cfg["max_age_seconds"],
        "rate_limit_per_minute": cfg["rate_limit_per_minute"],
        "mismatch_km": cfg["mismatch_km"],
        "fail_open": True,
        "fail_open_note": "Structural: the mismatch flag is only computed on the "
                          "usable branch. No configuration can disable this.",
        "statuses": [s.value for s in OperatorStatus],
        "consent_states": [c.value for c in ConsentState],
    }

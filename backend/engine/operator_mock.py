"""
`MockOperatorAdapter` — the local, synthetic operator used by every demo, test
and evaluation run in this project. It is the DEFAULT adapter and the only one
that returns data.

It reproduces the behaviour SIMShield had before the adapter boundary existed,
so scenarios and the detection page are unchanged, while adding the things a
real integration forces you to handle: consent, freshness, latency, rate limits
and malformed responses.

FIXTURE FORMAT
--------------
A scenario or profile states where the network says the SIM is by NAMING A
PLACE, not by giving a coordinate:

    {"sim_network_area": "Delhi"}          # preferred

The name is resolved against the public gazetteer in `engine.geo`, which holds
landmarks — not subscriber data. Distance is then measured from that anchor to
the claimed login location. The consequence is that no operator-derived
coordinate is ever constructed, so none can leak into a log, an audit record or
an evaluation report.

    {"sim_network_location": {"lat": .., "lon": ..}}   # legacy, deprecated

is still accepted so older fixtures keep working, but it is converted to an area
label immediately on entry and the coordinate is discarded.

FAULT INJECTION
---------------
`set_fault("timeout")` (or `subject["attempt"]["operator_fault"]` outside
production) makes the mock return a specific degraded result, which is how the
degradation matrix in `evaluate_operator.py` and the fail-open tests exercise
all nine failure modes without waiting on a real outage.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import deque

from . import geo, settings
from .operator_adapter import (ConsentState, OperatorAdapter, OperatorResult,
                               OperatorStatus, SimLocationData, SimSwapData,
                               now_iso, operator_config)

#: Faults a scenario or test may request, by name.
FAULTS = ("none", "unavailable", "timeout", "stale", "partial",
          "disagreement", "rate_limited", "malformed", "consent_withdrawn")

_FAULT_STATUS = {
    "unavailable": (OperatorStatus.UNAVAILABLE, "injected: operator unreachable"),
    "malformed": (OperatorStatus.MALFORMED, "injected: unparseable operator payload"),
    "partial": (OperatorStatus.PARTIAL, "injected: response missing the area field"),
    "disagreement": (OperatorStatus.SOURCE_DISAGREEMENT,
                     "injected: two network sources reported different areas"),
    "rate_limited": (OperatorStatus.RATE_LIMITED, "injected: operator quota exhausted"),
}


def _cell_id(area: str) -> str:
    """A stable synthetic cell identifier for an area label."""
    digest = hashlib.sha256(f"simshield-mock:{area}".encode("utf-8")).hexdigest()
    return f"CELL-{digest[:5].upper()}-{digest[5:9].upper()}"


class MockOperatorAdapter(OperatorAdapter):
    """Synthetic operator. Never performs I/O of any kind."""

    name = "mock:simshield-local/1.0"
    simulated = True

    def __init__(self, fault: str = "none"):
        self._fault = fault
        self._lock = threading.Lock()
        self._calls: dict[str, deque] = {}

    # --- fault control --------------------------------------------------------
    def set_fault(self, fault: str) -> None:
        if fault not in FAULTS:
            raise ValueError(f"unknown fault {fault!r}; expected one of {FAULTS}")
        self._fault = fault

    def _fault_for(self, subject: dict) -> str:
        """
        The active fault. A per-attempt override is honoured only outside
        production: it exists so a demo scenario can show an outage, and it
        must never be reachable from a real request body.
        """
        if not settings.is_production():
            attempt = subject.get("attempt") or {}
            injected = attempt.get("operator_fault")
            if injected in FAULTS:
                return injected
        return self._fault

    # --- rate limiting --------------------------------------------------------
    def _rate_limited(self, subject_id: str) -> bool:
        """Sliding-window quota per subject, mirroring a real operator's."""
        limit = int(operator_config()["rate_limit_per_minute"])
        if limit <= 0:
            return False
        now = time.monotonic()
        with self._lock:
            window = self._calls.setdefault(subject_id, deque())
            while window and now - window[0] > 60.0:
                window.popleft()
            if len(window) >= limit:
                return True
            window.append(now)
        return False

    def reset_quota(self) -> None:
        with self._lock:
            self._calls.clear()

    # --- area resolution ------------------------------------------------------
    def _reported_area(self, subject: dict) -> tuple[str, str | None] | None:
        """
        The area the network reports for this SIM, or None if it has no fix.

        Resolution order: the attempt (so a demo can state the case), then the
        profile. A legacy coordinate is collapsed to its nearest gazetteer
        entry here and the coordinate is not retained.
        """
        for holder in (subject.get("attempt") or {}, subject.get("profile") or {}):
            named = holder.get("sim_network_area")
            if named:
                place = _lookup_area(named)
                if place:
                    return place
            legacy = holder.get("sim_network_location")
            if legacy and legacy.get("lat") is not None:
                near = geo.nearest_place(float(legacy["lat"]), float(legacy["lon"]))
                return near["place"], near["country"]
        return None

    # --- operations -----------------------------------------------------------
    def sim_location(self, subject: dict, *, claimed: dict | None,
                     consent: ConsentState) -> OperatorResult:
        started = time.perf_counter()
        op = "sim_location"

        if not consent.permits_lookup:
            return self.degraded(op, OperatorStatus.CONSENT_DENIED,
                                 f"consent state is {consent.value}", consent=consent,
                                 latency_ms=_ms(started))

        fault = self._fault_for(subject)
        if fault == "consent_withdrawn":
            return self.degraded(op, OperatorStatus.CONSENT_DENIED,
                                 "injected: subscriber withdrew consent",
                                 consent=ConsentState.WITHDRAWN, latency_ms=_ms(started))
        if fault in _FAULT_STATUS:
            status, reason = _FAULT_STATUS[fault]
            return self.degraded(op, status, reason, consent=consent,
                                 latency_ms=_ms(started))
        if fault == "timeout":
            # Report a latency past the budget; `safe_call` also downgrades on
            # its own measurement, so neither layer alone is load-bearing.
            budget = float(operator_config()["timeout_ms"])
            return self.degraded(op, OperatorStatus.TIMEOUT,
                                 "injected: operator did not answer in time",
                                 consent=consent, latency_ms=budget * 2)

        subject_id = str(subject.get("id") or "anonymous")
        if self._rate_limited(subject_id):
            return self.degraded(op, OperatorStatus.RATE_LIMITED,
                                 "local quota for this subject exhausted",
                                 consent=consent, latency_ms=_ms(started))

        reported = self._reported_area(subject)
        claimed_ok = bool(claimed and claimed.get("lat") is not None)

        if reported is None:
            # No network fix. The phone's own location is reported back to the
            # subscriber for transparency, but typed as an ASSUMPTION so it can
            # never be scored as corroboration.
            if not claimed_ok:
                return self.degraded(op, OperatorStatus.UNAVAILABLE,
                                     "no network fix and no claimed location",
                                     consent=consent, latency_ms=_ms(started))
            near = geo.nearest_place(float(claimed["lat"]), float(claimed["lon"]))
            data = SimLocationData(
                area=near["place"], country=near["country"],
                cell_id=_cell_id(near["place"]), distance_km=0.0,
                distance_band=geo.distance_band(0.0), origin="device_assumption")
            return OperatorResult(
                status=OperatorStatus.ASSUMED_COLOCATED, source=self.name,
                consent=consent, fresh=True, age_seconds=0.0,
                latency_ms=_ms(started), simulated=True, operation=op,
                degraded_reason="no operator fix; assumed SIM is with the device",
                data=data, retrieved_at=now_iso())

        area, country = reported
        anchor = _anchor_for(area)
        distance_km = None
        if claimed_ok and anchor:
            distance_km = round(geo.haversine_km(
                float(claimed["lat"]), float(claimed["lon"]), anchor[0], anchor[1]), 1)

        age = _injected_age(subject, fault)
        max_age = float(operator_config()["max_age_seconds"])
        if age > max_age:
            return self.degraded(op, OperatorStatus.STALE,
                                 f"reading is {age:.0f}s old (limit {max_age:.0f}s)",
                                 consent=consent, latency_ms=_ms(started),
                                 age_seconds=age)

        data = SimLocationData(
            area=area, country=country, cell_id=_cell_id(area),
            distance_km=distance_km,
            distance_band=geo.distance_band(distance_km),
            origin="operator_feed")
        return OperatorResult(
            status=OperatorStatus.AVAILABLE, source=self.name, consent=consent,
            fresh=True, age_seconds=age, latency_ms=_ms(started), simulated=True,
            operation=op, data=data, retrieved_at=now_iso())

    def sim_swap_check(self, subject: dict, *, max_age_days: int,
                       consent: ConsentState) -> OperatorResult:
        started = time.perf_counter()
        op = "sim_swap_check"

        if not consent.permits_lookup:
            return self.degraded(op, OperatorStatus.CONSENT_DENIED,
                                 f"consent state is {consent.value}", consent=consent,
                                 latency_ms=_ms(started))

        fault = self._fault_for(subject)
        if fault == "consent_withdrawn":
            return self.degraded(op, OperatorStatus.CONSENT_DENIED,
                                 "injected: subscriber withdrew consent",
                                 consent=ConsentState.WITHDRAWN, latency_ms=_ms(started))
        if fault in _FAULT_STATUS:
            status, reason = _FAULT_STATUS[fault]
            return self.degraded(op, status, reason, consent=consent,
                                 latency_ms=_ms(started))
        if fault == "timeout":
            budget = float(operator_config()["timeout_ms"])
            return self.degraded(op, OperatorStatus.TIMEOUT,
                                 "injected: operator did not answer in time",
                                 consent=consent, latency_ms=budget * 2)

        subject_id = str(subject.get("id") or "anonymous")
        if self._rate_limited(subject_id):
            return self.degraded(op, OperatorStatus.RATE_LIMITED,
                                 "local quota for this subject exhausted",
                                 consent=consent, latency_ms=_ms(started))

        profile = subject.get("profile") or {}
        activated = profile.get("sim_activation_date")
        if not activated:
            return self.degraded(op, OperatorStatus.PARTIAL,
                                 "no activation date in the synthetic record",
                                 consent=consent, latency_ms=_ms(started))

        from .risk_engine import days_since
        age_days = days_since(activated)
        age = _injected_age(subject, fault)
        max_age_s = float(operator_config()["max_age_seconds"])
        if age > max_age_s:
            return self.degraded(op, OperatorStatus.STALE,
                                 f"reading is {age:.0f}s old (limit {max_age_s:.0f}s)",
                                 consent=consent, latency_ms=_ms(started),
                                 age_seconds=age)

        data = SimSwapData(
            swapped=age_days is not None and age_days <= max_age_days,
            sim_age_days=age_days, max_age_days=max_age_days,
            operator=profile.get("operator"))
        return OperatorResult(
            status=OperatorStatus.AVAILABLE, source=self.name, consent=consent,
            fresh=True, age_seconds=age, latency_ms=_ms(started), simulated=True,
            operation=op, data=data, retrieved_at=now_iso())


def _ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000.0


def _injected_age(subject: dict, fault: str) -> float:
    """Age of the reading in seconds. The mock reads live, so normally 0."""
    if fault == "stale":
        return float(operator_config()["max_age_seconds"]) * 10.0
    attempt = subject.get("attempt") or {}
    if not settings.is_production() and attempt.get("operator_age_seconds") is not None:
        try:
            return float(attempt["operator_age_seconds"])
        except (TypeError, ValueError):
            return 0.0
    return 0.0


def _lookup_area(named: str) -> tuple[str, str | None] | None:
    """Resolve a fixture's place name against the gazetteer (case-insensitive)."""
    target = named.strip().lower()
    for name, country, _lat, _lon in geo.GAZETTEER:
        if name.lower() == target or name.split(",")[0].strip().lower() == target:
            return name, country
    return None


def _anchor_for(area: str) -> tuple[float, float] | None:
    """The public landmark coordinate used as the measuring anchor for an area."""
    for name, _country, lat, lon in geo.GAZETTEER:
        if name == area:
            return lat, lon
    return None

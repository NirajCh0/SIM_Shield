"""
Operator-integration boundary: typed results and the adapter interface.

WHY THIS LAYER EXISTS
---------------------
Before this module, "ask the operator where the SIM is" was a plain function
that returned a dict, and the caller inferred availability from whether a key
was present. That is exactly the shape that produces a fail-CLOSED accident: a
missing key, a slow response or an empty payload all look alike, and one careless
`if not loc: risk += 65` turns an operator outage into a lockout for every
legitimate subscriber at once.

So the boundary is made explicit and typed. Every call returns an
`OperatorResult` that states, as separate fields that cannot be defaulted away:

    status      — did we get data, and if not, why not
    fresh       — is the data recent enough to act on (with age_seconds as evidence)
    latency_ms  — how long the call actually took (measured, not assumed)
    source      — which adapter produced this, named and versioned
    consent     — the subscriber's consent state for operator lookups

FAIL-OPEN IS STRUCTURAL
-----------------------
`usable` is true only when `status is AVAILABLE`. Every consumer of operator
data must gate on `result.usable`, and the one place that converts a result into
risk points (`engine.operator.location_mismatch`) computes `mismatch` INSIDE the
usable branch, so there is no reachable path where a degraded result raises a
score.

There is deliberately no `fail_open` configuration key. A flag can be flipped by
accident or by an attacker who can write config; a control-flow structure that
never adds points on the degraded path cannot be. `tests/test_operator_adapter.py`
asserts this behaviourally against all nine degradation modes, and
`evaluate_operator.py` measures it across the full scenario suite.

PRIVACY AT THE BOUNDARY
-----------------------
Operator-derived location is coarsened to an **area label** before it leaves the
adapter. Callers receive `area` + `distance_km` + `distance_band`; they never
receive an operator-reported coordinate, because one is never constructed from
subscriber data — the adapter resolves an area name to a public gazetteer anchor
and measures from that. Phone numbers, IMSIs and ICCIDs are not accepted as
adapter inputs at all: the subject is identified by an opaque profile id.

ALL DATA IS SYNTHETIC. No adapter in this project contacts a real network.
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from datetime import datetime

from .config_loader import load_config

# --- adapter identity ---------------------------------------------------------
# Bumped when the result contract changes, so an audit record from an old build
# is not mistaken for one produced under the current rules.
CONTRACT_VERSION = "1.0"


class OperatorStatus(str, enum.Enum):
    """
    Outcome of an operator call. Only AVAILABLE is usable for scoring.

    The degraded members are distinct rather than a single FAILED because the
    right operational response differs: TIMEOUT and RATE_LIMITED say retry
    later, MALFORMED says the operator broke its contract, CONSENT_DENIED says
    never retry without asking the subscriber, and NOT_CONFIGURED says this
    deployment has no operator agreement at all.
    """

    AVAILABLE = "available"
    #: No operator fix exists, so the device's own location was used on the
    #: assumption that a phone and its SIM travel together. Reportable to the
    #: subscriber, but NEVER scored — it is an assumption, not evidence, and
    #: treating it as evidence would mean every user "matches" themselves.
    ASSUMED_COLOCATED = "assumed_colocated"
    UNAVAILABLE = "unavailable"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    MALFORMED = "malformed"
    STALE = "stale"
    #: Data arrived but a field the decision needs is missing.
    PARTIAL = "partial"
    #: Two operator sources returned irreconcilable answers; with no tie-break
    #: rule, acting on either would be a coin flip.
    SOURCE_DISAGREEMENT = "source_disagreement"
    CONSENT_DENIED = "consent_denied"
    NOT_CONFIGURED = "not_configured"


class ConsentState(str, enum.Enum):
    """Consent for operator lookups, checked at the adapter boundary."""

    GRANTED = "granted"
    WITHDRAWN = "withdrawn"
    DENIED = "denied"
    #: Policy does not require consent for this purpose (e.g. fraud prevention
    #: under a legitimate-interest basis). Still recorded explicitly.
    NOT_REQUIRED = "not_required"
    UNKNOWN = "unknown"

    @property
    def permits_lookup(self) -> bool:
        return self in (ConsentState.GRANTED, ConsentState.NOT_REQUIRED)


# --- payloads -----------------------------------------------------------------
@dataclass(frozen=True)
class SimSwapData:
    """CAMARA `sim-swap/check` payload: has this SIM changed recently?"""

    swapped: bool
    sim_age_days: float | None
    max_age_days: int
    operator: str | None


@dataclass(frozen=True)
class SimLocationData:
    """
    CAMARA `location-retrieval` payload, already coarsened.

    There is no `lat`/`lon` field by design. `distance_km` is a scalar derived
    inside the adapter by measuring the claimed login location against a public
    gazetteer anchor for the reported area; it discloses far less than a fix and
    is what the mismatch rule actually needs.
    """

    area: str
    country: str | None
    cell_id: str
    distance_km: float | None
    distance_band: str
    #: Where the area came from: "operator_feed" or "device_assumption".
    origin: str


@dataclass(frozen=True)
class OperatorResult:
    """
    One operator call, fully described.

    No field has a default that could hide a problem: `status`, `source`,
    `consent`, `fresh`, `age_seconds` and `latency_ms` are all required at
    construction. Use `degraded()` to build a non-AVAILABLE result — it is the
    only ergonomic path, so "I couldn't get data" is always as easy to express
    correctly as "I could".
    """

    status: OperatorStatus
    source: str
    consent: ConsentState
    fresh: bool
    age_seconds: float | None
    latency_ms: float
    simulated: bool
    operation: str
    contract_version: str = CONTRACT_VERSION
    degraded_reason: str | None = None
    data: SimSwapData | SimLocationData | None = None
    retrieved_at: str | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def usable(self) -> bool:
        """
        True only when this result may influence a risk decision.

        Note the conjunction: AVAILABLE alone is not enough. Data that arrived
        successfully but is stale, unconsented or empty is not evidence, and
        the property refuses to pretend otherwise.
        """
        return (self.status is OperatorStatus.AVAILABLE
                and self.fresh
                and self.consent.permits_lookup
                and self.data is not None)

    @property
    def degraded(self) -> bool:
        return not self.usable

    def audit_fields(self) -> dict:
        """
        The subset of this result that may be written to the audit log.

        Explicitly an allowlist, not a redaction pass: adding a field to the
        payload types must not silently start logging it. Nothing here is
        personal data — no area, cell id, coordinate, phone number or IMSI.
        `tests/test_operator_adapter.py` asserts that against the real log.
        """
        return {
            "operation": self.operation,
            "status": self.status.value,
            "usable": self.usable,
            "fresh": self.fresh,
            "age_seconds": None if self.age_seconds is None else round(self.age_seconds, 1),
            "latency_ms": round(self.latency_ms, 1),
            "source": self.source,
            "consent": self.consent.value,
            "simulated": self.simulated,
            "contract_version": self.contract_version,
            "degraded_reason": self.degraded_reason,
        }

    def explain(self) -> dict:
        """A user-facing summary of why operator data did or did not count."""
        return {
            "status": self.status.value,
            "usable": self.usable,
            "source": self.source,
            "consent": self.consent.value,
            "fresh": self.fresh,
            "simulated": self.simulated,
            "message": _STATUS_MESSAGES.get(
                self.status, "Operator data was not usable for this check."),
            "affects_risk": self.usable,
        }


_STATUS_MESSAGES = {
    OperatorStatus.AVAILABLE:
        "Your operator confirmed where this number's SIM is registered.",
    OperatorStatus.ASSUMED_COLOCATED:
        "No separate network reading was available, so we assumed your SIM is "
        "with your phone. This assumption never adds risk on its own.",
    OperatorStatus.UNAVAILABLE:
        "Your operator's service could not be reached, so this check was "
        "skipped. It cannot block a genuine sign-in.",
    OperatorStatus.TIMEOUT:
        "Your operator did not answer in time, so this check was skipped.",
    OperatorStatus.RATE_LIMITED:
        "We have queried your operator too often just now, so this check was "
        "skipped.",
    OperatorStatus.MALFORMED:
        "Your operator returned an unreadable answer, so this check was skipped.",
    OperatorStatus.STALE:
        "The last network reading was too old to rely on, so it was ignored.",
    OperatorStatus.PARTIAL:
        "Your operator's answer was incomplete, so it was ignored.",
    OperatorStatus.SOURCE_DISAGREEMENT:
        "Network sources disagreed about this SIM, so neither was used.",
    OperatorStatus.CONSENT_DENIED:
        "You have not consented to network SIM lookups, so none was made.",
    OperatorStatus.NOT_CONFIGURED:
        "No operator integration is configured in this deployment.",
}


class OperatorAdapter:
    """
    Interface every operator integration implements.

    Contract for implementers:
      * NEVER raise. A network integration that throws puts the caller in
        control of failing open, and callers forget. Catch everything and
        return `degraded(...)` instead — `safe_call` enforces this even for a
        buggy adapter.
      * NEVER accept or return a phone number, IMSI, ICCID or coordinate.
      * Always measure latency; never report an assumed value.
    """

    name = "abstract"
    simulated = True

    def sim_swap_check(self, subject: dict, *, max_age_days: int,
                       consent: ConsentState) -> OperatorResult:
        raise NotImplementedError

    def sim_location(self, subject: dict, *, claimed: dict | None,
                     consent: ConsentState) -> OperatorResult:
        raise NotImplementedError

    # --- helpers for implementers --------------------------------------------
    def degraded(self, operation: str, status: OperatorStatus, reason: str,
                 *, consent: ConsentState = ConsentState.UNKNOWN,
                 latency_ms: float = 0.0,
                 age_seconds: float | None = None) -> OperatorResult:
        return OperatorResult(
            status=status, source=self.name, consent=consent,
            fresh=False, age_seconds=age_seconds, latency_ms=latency_ms,
            simulated=self.simulated, operation=operation,
            degraded_reason=reason, data=None)


def safe_call(adapter: OperatorAdapter, operation: str, subject: dict,
              consent: ConsentState, **kwargs) -> OperatorResult:
    """
    Invoke an adapter operation with the fail-open guarantee enforced OUTSIDE
    the adapter.

    Even a correct adapter can be handed a malformed profile, and a future
    adapter may be written by someone who did not read the contract above. This
    wrapper converts any escaping exception, any non-`OperatorResult` return and
    any over-budget latency into a typed degraded result, so the detection
    engine cannot be made to fail closed by an adapter bug.
    """
    budget_ms = float(operator_config().get("timeout_ms", 800))
    started = time.perf_counter()
    try:
        result = getattr(adapter, operation)(subject, consent=consent, **kwargs)
    except Exception as exc:                       # noqa: BLE001 — deliberate
        elapsed = (time.perf_counter() - started) * 1000.0
        return OperatorResult(
            status=OperatorStatus.UNAVAILABLE, source=getattr(adapter, "name", "unknown"),
            consent=consent, fresh=False, age_seconds=None, latency_ms=elapsed,
            simulated=getattr(adapter, "simulated", True), operation=operation,
            degraded_reason=f"adapter raised {type(exc).__name__}", data=None)

    if not isinstance(result, OperatorResult):
        elapsed = (time.perf_counter() - started) * 1000.0
        return OperatorResult(
            status=OperatorStatus.MALFORMED, source=getattr(adapter, "name", "unknown"),
            consent=consent, fresh=False, age_seconds=None, latency_ms=elapsed,
            simulated=getattr(adapter, "simulated", True), operation=operation,
            degraded_reason="adapter returned a non-OperatorResult value", data=None)

    # A result that arrived over budget is downgraded here rather than trusted,
    # so a slow operator degrades the check instead of delaying every login.
    if result.usable and result.latency_ms > budget_ms:
        return OperatorResult(
            status=OperatorStatus.TIMEOUT, source=result.source, consent=result.consent,
            fresh=False, age_seconds=result.age_seconds, latency_ms=result.latency_ms,
            simulated=result.simulated, operation=operation,
            degraded_reason=f"exceeded {budget_ms:.0f} ms budget", data=None)
    return result


# --- configuration and adapter selection --------------------------------------
def operator_config() -> dict:
    """The `operator:` block from config.yaml, with conservative fallbacks."""
    cfg = load_config().get("operator") or {}
    return {
        "adapter": cfg.get("adapter", "mock"),
        "timeout_ms": cfg.get("timeout_ms", 800),
        "max_age_seconds": cfg.get("max_age_seconds", 300),
        "rate_limit_per_minute": cfg.get("rate_limit_per_minute", 30),
        "mismatch_km": cfg.get("mismatch_km", 100),
    }


_adapter: OperatorAdapter | None = None


def get_adapter() -> OperatorAdapter:
    """The configured adapter (cached). Defaults to the local mock."""
    global _adapter
    if _adapter is None:
        _adapter = _build_adapter(operator_config()["adapter"])
    return _adapter


def _build_adapter(kind: str) -> OperatorAdapter:
    from .operator_camara import CamaraOperatorAdapter
    from .operator_mock import MockOperatorAdapter

    if kind == "camara":
        return CamaraOperatorAdapter()
    if kind != "mock":
        # An unknown name must not silently fall back to something that looks
        # real. The mock is the safe default, but say so loudly.
        import logging
        logging.getLogger(__name__).warning(
            "Unknown operator adapter %r; using the local mock.", kind)
    return MockOperatorAdapter()


def set_adapter(adapter: OperatorAdapter | None) -> None:
    """Install an adapter (tests and the degradation harness). None resets."""
    global _adapter
    _adapter = adapter


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")

"""
`CamaraOperatorAdapter` — a DOCUMENTED, NON-OPERATIONAL PLACEHOLDER.

This file contains no network client, no credentials, no endpoint hostnames and
no request-building code. It exists to record, in one reviewable place, what a
real GSMA Open Gateway / CAMARA integration would require — and to make the
absence of one explicit in the type system rather than implied by a comment.

Every call returns `OperatorStatus.NOT_CONFIGURED`, which is not usable, so
selecting this adapter degrades SIMShield to its non-operator signals and
changes no decision in the fail-open direction. Nothing here has ever contacted
a mobile network, and this project makes no claim of operator integration.

WHAT A REAL INTEGRATION WOULD NEED (none of it is implemented)
-------------------------------------------------------------
Commercial and legal
  * A signed agreement with each operator (NTC / Ncell / Smart Cell) and an
    aggregator or direct Open Gateway onboarding.
  * A lawful basis under Nepal's privacy law for processing SIM status and
    network location, plus a Data Processing Agreement.
  * Recorded, revocable subscriber consent per purpose. CAMARA carries this as
    a three-legged OAuth2 flow (CIBA), where the subscriber — not the bank —
    authorises the lookup.

Technical
  * OAuth2 client-credentials for service-to-service auth, plus the CIBA flow
    above for subscriber-authorised location retrieval.
  * mTLS to the operator gateway, with certificate pinning and rotation.
  * Idempotency keys, retry with jitter, a circuit breaker, and a per-operator
    quota tracker — an operator quota is shared across a bank's whole estate.
  * Response-schema validation on every field, because a partner API changing
    shape must degrade this system, not crash it.
  * Per-call audit with the subscriber pseudonymised (already provided by
    `engine.compliance.record_operator_access`).

Endpoints the real service exposes (named for documentation only; this file
never calls them):
    POST  sim-swap/v0/check                — has the SIM changed within N days
    POST  location-retrieval/v0/retrieve   — network-reported location

WHY THIS IS NOT IMPLEMENTED HERE
--------------------------------
Access to these APIs requires a commercial relationship an academic prototype
cannot hold, and exercising them requires real subscribers' data. Implementing a
client that could be pointed at a real gateway would add risk without adding any
evaluable result, so the boundary is defined and the implementation is not
written. This is a scope decision, stated plainly, not an oversight.
"""
from __future__ import annotations

from .operator_adapter import (ConsentState, OperatorAdapter, OperatorResult,
                               OperatorStatus)

#: Everything a deployment would have to supply. All unset, by design.
REQUIRED_SETTINGS = (
    "SIMSHIELD_CAMARA_BASE_URL",
    "SIMSHIELD_CAMARA_CLIENT_ID",
    "SIMSHIELD_CAMARA_CLIENT_SECRET",
    "SIMSHIELD_CAMARA_MTLS_CERT",
    "SIMSHIELD_CAMARA_MTLS_KEY",
)


class CamaraNotImplemented(RuntimeError):
    """Raised if anything tries to make this placeholder perform a real call."""


class CamaraOperatorAdapter(OperatorAdapter):
    """
    Placeholder for a real CAMARA client. Returns NOT_CONFIGURED, always.

    `simulated` stays True: nothing in this class can produce real data, and a
    result that claimed otherwise would be a false provenance record in the
    audit log.
    """

    name = "camara:placeholder/not-configured"
    simulated = True
    implemented = False

    def _not_configured(self, operation: str, consent: ConsentState) -> OperatorResult:
        return self.degraded(
            operation, OperatorStatus.NOT_CONFIGURED,
            "CAMARA adapter is a documented placeholder; no operator agreement, "
            "credentials or client exist in this project",
            consent=consent, latency_ms=0.0)

    def sim_swap_check(self, subject: dict, *, max_age_days: int,
                       consent: ConsentState) -> OperatorResult:
        return self._not_configured("sim_swap_check", consent)

    def sim_location(self, subject: dict, *, claimed: dict | None,
                     consent: ConsentState) -> OperatorResult:
        return self._not_configured("sim_location", consent)

    # A deliberate tripwire: if a future change ever wires a transport in here,
    # it fails loudly at the seam instead of quietly acquiring live telecom
    # access. Nothing in SIMShield calls this.
    def _perform_request(self, *args, **kwargs):
        raise CamaraNotImplemented(
            "SIMShield does not implement live operator calls. Implementing one "
            "requires an operator agreement, subscriber consent under a lawful "
            "basis, and an ethics review — see the module docstring.")

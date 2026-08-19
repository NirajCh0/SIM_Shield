"""
Loads config.yaml + compliance.yaml once and exposes them to the engine.

Keeping configuration out of the code means scoring weights, thresholds, safe
zones, AND the privacy/compliance policy can all be tuned for a demo without
editing Python. The split mirrors production practice: detection tuning
(config.yaml) is owned by the fraud team; the privacy/retention/consent policy
(compliance.yaml) is owned by the DPO / compliance team.
"""
import os
import yaml

# backend/ directory, regardless of where the process is launched from.
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BACKEND_DIR, "config.yaml")
COMPLIANCE_PATH = os.path.join(BACKEND_DIR, "compliance.yaml")

_cache = None
_compliance_cache = None


def load_config(force_reload: bool = False) -> dict:
    """Return the parsed detection config dict (cached after first load)."""
    global _cache
    if _cache is None or force_reload:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            _cache = yaml.safe_load(f)
    return _cache


def load_compliance(force_reload: bool = False) -> dict:
    """Return the parsed privacy/compliance config dict (cached)."""
    global _compliance_cache
    if _compliance_cache is None or force_reload:
        with open(COMPLIANCE_PATH, "r", encoding="utf-8") as f:
            _compliance_cache = yaml.safe_load(f)
    return _compliance_cache


_reason_cache = None


def load_reason_codes(force_reload: bool = False) -> dict:
    """
    The fraud-analyst reason-code taxonomy (reason_codes.yaml).

    Kept out of the code for the same reason the detection weights are: the
    taxonomy is owned by the fraud team, and adding a code must not require a
    deployment. It is loaded once and cached.
    """
    global _reason_cache
    if _reason_cache is None or force_reload:
        path = os.path.join(BACKEND_DIR, "reason_codes.yaml")
        with open(path, "r", encoding="utf-8") as f:
            _reason_cache = yaml.safe_load(f)
    return _reason_cache


def backend_path(*parts: str) -> str:
    """Resolve a path relative to the backend/ directory."""
    return os.path.join(BACKEND_DIR, *parts)

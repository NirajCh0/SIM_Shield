"""
Unsupervised + sequential anomaly detection (complements the Random Forest).

1. Isolation Forest (unsupervised) — trained by train_model.py on the LEGIT
   rows of the 100k dataset over the same 11 telecom features. At scoring time
   it answers "how unlike normal traffic is this login?" without using labels,
   which catches novel fraud patterns the supervised model was never shown.
   Loaded lazily from models/iso_model.joblib; the system degrades gracefully
   (returns None) when the file or sklearn is missing.

2. Sequence model (Markov chain) — a lightweight per-user model of login
   behaviour over time. Each login event is discretised into a token
   (time-of-day bucket x device familiarity) and an order-1 Markov transition
   matrix is fitted to the user's own history; an improbable transition scores
   high. This is the prototype stand-in for the LSTM/GRU sequence model the
   architecture calls for — production would train an LSTM on real event
   streams, but the interface (events in, 0-100 anomaly out) is the same, so
   the swap is contained to this module.
"""
import math
import os
from collections import defaultdict
from datetime import datetime

from .config_loader import backend_path, load_config

_iso_model = None
_iso_loaded = False


# --- 1. Isolation Forest -------------------------------------------------------
def _load_iso():
    """Integrity-verified load — see engine/artifacts.py (finding F20)."""
    global _iso_model, _iso_loaded
    _iso_loaded = True
    from . import artifacts
    cfg = load_config()
    _iso_model = artifacts.safe_load(
        backend_path(cfg["ml"].get("iso_model_path", "models/iso_model.joblib")))
    # Same reasoning as engine/ml_model.py: n_jobs is pickled into the artefact,
    # and parallel dispatch costs more than it saves when scoring one login.
    from .ml_model import _tune_for_inference
    _tune_for_inference(_iso_model)


def iso_available() -> bool:
    if not _iso_loaded:
        _load_iso()
    return _iso_model is not None


def get_anomaly_score(features: dict) -> float | None:
    """
    0..1 'unlike normal traffic' score from the Isolation Forest, or None when
    no model is loaded. decision_function > 0 means inlier; the sigmoid maps
    the typical [-0.3, 0.3] range onto (0, 1) with 0.5 at the boundary.
    """
    if not iso_available():
        return None
    cfg = load_config()
    X = [[features[name] for name in cfg["ml"]["features"]]]
    d = float(_iso_model.decision_function(X)[0])
    return round(1.0 / (1.0 + math.exp(10.0 * d)), 4)


# --- 2. Sequential (Markov) login-behaviour model -------------------------------
def _hour_bucket(hour: int) -> str:
    if 0 <= hour < 6:
        return "night"
    if 6 <= hour < 12:
        return "morning"
    if 12 <= hour < 18:
        return "day"
    return "evening"


def event_token(timestamp: str, device_known: bool) -> str:
    """Discretise one login event into a Markov state token."""
    try:
        hour = datetime.fromisoformat(timestamp).hour
    except (ValueError, TypeError):
        hour = 12
    return f"{_hour_bucket(hour)}|{'known' if device_known else 'new'}"


def sequence_anomaly(history_tokens: list[str], next_token: str,
                     min_history: int = 5) -> dict:
    """
    Fit an order-1 Markov chain to the user's own login-event history and score
    how improbable the incoming event is given the last state.

    Returns {"score": 0-100 | None, "probability": p | None, "n_history": n}.
    score None => not enough history to judge (never punish new users).
    """
    n = len(history_tokens)
    if n < min_history:
        return {"score": None, "probability": None, "n_history": n}

    # transition counts with add-one smoothing over the observed vocabulary
    vocab = set(history_tokens) | {next_token}
    trans: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for a, b in zip(history_tokens, history_tokens[1:]):
        trans[a][b] += 1

    last = history_tokens[-1]
    row = trans[last]
    total = sum(row.values()) + len(vocab)          # +1 smoothing per vocab token
    p = (row.get(next_token, 0) + 1) / total

    # improbability -> 0-100 (p >= 0.5 ~ 0 risk; p -> 0 ~ 100 risk)
    score = round(min(100.0, max(0.0, -math.log2(max(p, 1e-9)) * 20.0 - 20.0)), 1)
    return {"score": score, "probability": round(p, 4), "n_history": n}

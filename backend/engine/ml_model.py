"""
Component 3: the ML classifier (Random Forest trained on the real 100k dataset).

A thin, swappable wrapper around a scikit-learn model. The rest of the system
never imports sklearn directly, so the model can be retrained, replaced, or
removed without touching the API. If the model file or sklearn is missing, the
system degrades gracefully: get_fraud_probability() returns None and the fusion
step drops the ML component and renormalises the remaining weights.

Feature order is taken from config.yaml -> ml.features, which matches
train_model.py and engine/telecom_features.build().
"""
import os

from .config_loader import backend_path, load_config

_model = None
_loaded = False  # whether we've attempted a load yet


def _load():
    """
    Load the Random Forest, but only after verifying its SHA-256 against the
    trusted manifest (finding F20) — unpickling an unverified artefact is
    arbitrary code execution. A failure degrades to rules-only rather than
    loading anyway.
    """
    global _model, _loaded
    _loaded = True
    from . import artifacts
    cfg = load_config()
    _model = artifacts.safe_load(backend_path(cfg["ml"]["model_path"]))
    _tune_for_inference(_model)


def _tune_for_inference(model) -> None:
    """
    Force single-process prediction on a model trained with `n_jobs=-1`.

    `n_jobs` is pickled INTO the artefact, so a forest fitted across every core
    also tries to *predict* across every core. That is right for fitting 300
    trees once and wrong for scoring one login: the joblib dispatch costs far
    more than the work it distributes. Measured here, single-row
    `predict_proba` is **3.5x faster** with `n_jobs=1` (14 ms vs 48 ms), and
    the parallel path is also what emitted tens of thousands of
    `sklearn.utils.parallel.delayed` warnings during the evaluation harnesses.

    Scoring in this system is per-request and single-row, so this is the
    correct setting everywhere the model is used at inference time. Training
    keeps `n_jobs=-1` in train_model.py, where it genuinely helps.
    """
    if model is not None and hasattr(model, "n_jobs"):
        model.n_jobs = 1


def is_available() -> bool:
    if not _loaded:
        _load()
    return _model is not None


def feature_vector(features: dict, cfg: dict) -> list:
    """Order the feature dict exactly as the model was trained."""
    return [features[name] for name in cfg["ml"]["features"]]


def _fraud_index() -> int:
    classes = list(_model.classes_)     # class 1 == fraud (see train_model.py)
    return classes.index(1) if 1 in classes else 1


def get_fraud_probability(features: dict) -> float | None:
    """
    Return P(fraud) in 0..1, or None if no model is loaded.
    `features` must contain every name listed in config.yaml -> ml.features.
    """
    if not is_available():
        return None
    cfg = load_config()
    X = [feature_vector(features, cfg)]
    return float(_model.predict_proba(X)[0][_fraud_index()])


def get_fraud_probabilities(rows: list[dict]) -> list | None:
    """
    Vectorised P(fraud) for many feature dicts in ONE model call (used by the
    evaluation harness; far faster than calling get_fraud_probability per row).
    """
    if not is_available():
        return None
    cfg = load_config()
    X = [feature_vector(r, cfg) for r in rows]
    return [float(p) for p in _model.predict_proba(X)[:, _fraud_index()]]

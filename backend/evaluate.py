"""
Evaluation harness - the 'mixed-methods evaluation' report generator.

Produces one JSON report (data/evaluation_report.json) with two halves:

  QUANTITATIVE (system / detection)
    * Detection metrics of the ML model on a held-out split of the 100k dataset:
      accuracy, precision, recall, F1, ROC-AUC, confusion matrix.
    * End-to-end decision distribution of the FULL fused engine over the built-in
      demo scenarios (does the whole pipeline behave as designed?).

  QUANTITATIVE + QUALITATIVE (user study)
    * The aggregated user-study results from engine.study.aggregate()
      (knowledge gain, SUS, confidence shift, and the pooled free-text feedback).

Run:  python evaluate.py
The metrics dashboard (frontend/metrics.html -> /api/evaluation) reads this file.
"""
import csv
import json

from sklearn.metrics import (confusion_matrix,
                             precision_recall_fscore_support, roc_auc_score)
from sklearn.model_selection import train_test_split

from engine import ml_model, study
from engine.config_loader import backend_path, load_config


def detection_metrics(cfg) -> dict:
    """Re-evaluate the trained model on a held-out split of the dataset."""
    if not ml_model.is_available():
        return {"available": False,
                "note": "No trained model found - run train_model.py first."}

    path = backend_path(cfg["ml"]["dataset_path"])
    features, target = cfg["ml"]["features"], cfg["ml"]["target_column"]
    X, y = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            X.append({name: float(row[name]) for name in features})
            y.append(int(float(row[target])))

    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    proba = ml_model.get_fraud_probabilities(X_test)   # one vectorised call
    pred = [1 if p >= 0.5 else 0 for p in proba]
    p, r, f1, _ = precision_recall_fscore_support(
        y_test, pred, average="binary", pos_label=1, zero_division=0)
    acc = sum(int(a == b) for a, b in zip(pred, y_test)) / len(y_test)

    return {
        "available": True,
        "n_test": len(y_test),
        "accuracy": round(acc, 4),
        "precision_fraud": round(p, 4),
        "recall_fraud": round(r, 4),
        "f1_fraud": round(f1, 4),
        "roc_auc": round(roc_auc_score(y_test, proba), 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
        "confusion_labels": "[[TN, FP], [FN, TP]]",
    }


def scenario_metrics() -> dict:
    """Run the built-in demo scenarios through the FULL fused engine."""
    from engine.detector import score_login
    from scenarios import SCENARIOS  # defined alongside this file

    rows, correct = [], 0
    for sc in SCENARIOS:
        result = score_login(sc["attempt"], sc["profile"])
        ok = result["decision"] == sc["expected_decision"]
        correct += int(ok)
        rows.append({"name": sc["name"], "expected": sc["expected_decision"],
                     "got": result["decision"], "risk_score": result["risk_score"],
                     "match": ok})
    return {"n": len(SCENARIOS), "matched": correct, "cases": rows}


def main():
    cfg = load_config()
    report = {
        "detection": detection_metrics(cfg),
        "scenarios": scenario_metrics(),
        "user_study": study.aggregate(),
    }
    out = backend_path("data", "evaluation_report.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(json.dumps(report["detection"], indent=2))
    print("\nScenario decisions:")
    for c in report["scenarios"]["cases"]:
        mark = "OK " if c["match"] else "XX "
        print(f"  {mark}{c['name']:28s} expected {c['expected']:8s} "
              f"got {c['got']:8s} (risk {c['risk_score']})")
    print(f"\nUser study: n={report['user_study']['n']}, "
          f"SUS={report['user_study']['sus_mean']}, "
          f"knowledge gain={report['user_study']['knowledge_gain_mean']}")
    print(f"\nWrote report -> {out}")


if __name__ == "__main__":
    main()

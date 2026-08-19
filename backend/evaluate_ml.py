"""
Honest ML evaluation (finding F23 / P2.12).

    python evaluate_ml.py

WHY THIS EXISTS SEPARATELY FROM evaluate.py
The original report headlined **accuracy** on a dataset that is ~74% fraud. On
that class balance a model predicting "fraud" for everything scores 74%, so
accuracy carries almost no information and flatters the system badly. This
script reports the measures that actually characterise a fraud detector:

  * PR-AUC (average precision) — the right summary under class imbalance
  * precision / recall / F1 for the fraud class
  * false-positive rate — what the system costs legitimate customers
  * Brier score + a calibration table — are the probabilities meaningful?
  * confusion matrix
  * bootstrap 95% confidence intervals — is the difference real or noise?

METHODOLOGY
A three-way split: train / threshold-tuning / FINAL HELD-OUT test. The held-out
portion is touched exactly once, at the end, and is never used to pick a
threshold — otherwise the reported numbers are optimistic by construction.

Ablations quantify what each component contributes, and an adversarial section
tests behaviour when the operator feed is missing, when the browser location is
spoofed, and on legitimate-but-unusual cases.

EVERYTHING BELOW IS SYNTHETIC. These numbers characterise a model trained on
generated data with an unrealistic fraud base rate. They are NOT evidence of
real-world performance and the model is NOT validated for deployment.
"""
import csv
import json
import random
import statistics
import sys

from engine.config_loader import backend_path, load_config

random.seed(20260813)


def load_dataset(cfg):
    path = backend_path(cfg["ml"]["dataset_path"])
    features = cfg["ml"]["features"]
    target = cfg["ml"]["target_column"]
    X, y = [], []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            X.append([float(row[name]) for name in features])
            y.append(int(float(row[target])))
    return X, y, features


# --- metrics ------------------------------------------------------------------
def confusion(y_true, y_pred):
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    return tn, fp, fn, tp


def metrics(y_true, y_pred, y_prob=None):
    tn, fp, fn, tp = confusion(y_true, y_pred)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    out = {
        "n": len(y_true),
        "positive_rate": round(sum(y_true) / len(y_true), 4),
        "accuracy": round((tp + tn) / len(y_true), 4),
        "precision_fraud": round(precision, 4),
        "recall_fraud": round(recall, 4),
        "f1_fraud": round(f1, 4),
        # The cost borne by legitimate customers — the number a bank cares about.
        "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
        "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) else 0.0,
        "confusion_matrix": [[tn, fp], [fn, tp]],
        "confusion_labels": "[[TN, FP], [FN, TP]]",
    }
    if y_prob is not None:
        out["brier_score"] = round(
            sum((p - t) ** 2 for p, t in zip(y_prob, y_true)) / len(y_true), 4)
    return out


def bootstrap_ci(y_true, y_pred, metric_fn, rounds=200):
    """Percentile bootstrap 95% CI — is a reported difference real or noise?"""
    n = len(y_true)
    if n == 0:
        return None
    vals = []
    idx = range(n)
    for _ in range(rounds):
        sample = [random.choice(idx) for _ in range(n)]
        yt = [y_true[i] for i in sample]
        yp = [y_pred[i] for i in sample]
        vals.append(metric_fn(yt, yp))
    vals.sort()
    lo = vals[int(0.025 * len(vals))]
    hi = vals[int(0.975 * len(vals)) - 1]
    return [round(lo, 4), round(hi, 4)]


def calibration_table(y_true, y_prob, bins=10):
    """Predicted probability vs. observed frequency — is 0.8 really 80%?"""
    rows = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        members = [(p, t) for p, t in zip(y_prob, y_true)
                   if (lo <= p < hi) or (b == bins - 1 and p == 1.0)]
        if not members:
            continue
        rows.append({
            "bin": f"{lo:.1f}-{hi:.1f}",
            "n": len(members),
            "mean_predicted": round(sum(p for p, _ in members) / len(members), 4),
            "observed_frequency": round(sum(t for _, t in members) / len(members), 4),
        })
    return rows


def average_precision(y_true, y_prob):
    """PR-AUC by the step-wise definition — the headline under imbalance."""
    pairs = sorted(zip(y_prob, y_true), key=lambda x: -x[0])
    total_pos = sum(y_true)
    if total_pos == 0:
        return 0.0
    tp = fp = 0
    prev_recall = 0.0
    ap = 0.0
    for _, t in pairs:
        if t == 1:
            tp += 1
        else:
            fp += 1
        precision = tp / (tp + fp)
        recall = tp / total_pos
        ap += precision * (recall - prev_recall)
        prev_recall = recall
    return round(ap, 4)


def main():
    try:
        from sklearn.ensemble import IsolationForest, RandomForestClassifier
        from sklearn.model_selection import train_test_split
    except ImportError:
        print("scikit-learn is required: pip install -r requirements.txt")
        return 1

    cfg = load_config()
    X, y, features = load_dataset(cfg)
    print(f"Loaded {len(X):,} synthetic rows · fraud base rate "
          f"{sum(y)/len(y):.1%}")
    print("NOTE: this base rate is unrealistic. A real deployment sees <1% "
          "fraud, so every figure below is optimistic.\n")

    # Three-way split. `tune` picks thresholds; `test` is touched ONCE.
    X_tr, X_tmp, y_tr, y_tmp = train_test_split(
        X, y, test_size=0.40, random_state=42, stratify=y)
    X_tune, X_test, y_tune, y_test = train_test_split(
        X_tmp, y_tmp, test_size=0.50, random_state=42, stratify=y_tmp)
    print(f"split: train {len(X_tr):,} · tune {len(X_tune):,} · "
          f"HELD-OUT test {len(X_test):,}\n")

    rf = RandomForestClassifier(n_estimators=300, max_depth=12,
                                min_samples_leaf=3, class_weight="balanced",
                                n_jobs=-1, random_state=42)
    rf.fit(X_tr, y_tr)
    fraud_idx = list(rf.classes_).index(1)

    # Threshold chosen on the TUNE split only.
    tune_prob = [float(p) for p in rf.predict_proba(X_tune)[:, fraud_idx]]
    best_t, best_f1 = 0.5, -1.0
    for t in [i / 100 for i in range(5, 96, 5)]:
        pred = [1 if p >= t else 0 for p in tune_prob]
        m = metrics(y_tune, pred)
        if m["f1_fraud"] > best_f1:
            best_t, best_f1 = t, m["f1_fraud"]
    print(f"threshold {best_t:.2f} selected on the tune split (F1={best_f1:.3f})\n")

    # --- final held-out evaluation ------------------------------------------
    test_prob = [float(p) for p in rf.predict_proba(X_test)[:, fraud_idx]]
    test_pred = [1 if p >= best_t else 0 for p in test_prob]
    final = metrics(y_test, test_pred, test_prob)
    final["pr_auc_average_precision"] = average_precision(y_test, test_prob)
    final["threshold"] = best_t
    final["recall_ci95"] = bootstrap_ci(
        y_test, test_pred,
        lambda t, p: (sum(1 for a, b in zip(t, p) if a == 1 and b == 1) /
                      max(1, sum(t))))
    final["precision_ci95"] = bootstrap_ci(
        y_test, test_pred,
        lambda t, p: (sum(1 for a, b in zip(t, p) if a == 1 and b == 1) /
                      max(1, sum(p))))
    final["calibration"] = calibration_table(y_test, test_prob)

    print("=== HELD-OUT TEST (used once, never for tuning) ===")
    for k in ("n", "positive_rate", "pr_auc_average_precision", "precision_fraud",
              "recall_fraud", "f1_fraud", "false_positive_rate",
              "false_negative_rate", "brier_score", "accuracy"):
        print(f"  {k:28s} {final[k]}")
    print(f"  {'recall 95% CI':28s} {final['recall_ci95']}")
    print(f"  {'precision 95% CI':28s} {final['precision_ci95']}")
    print(f"  {'confusion [[TN,FP],[FN,TP]]':28s} {final['confusion_matrix']}")
    print("\n  calibration (predicted vs observed):")
    for row in final["calibration"]:
        print(f"    {row['bin']:>9}  n={row['n']:>6}  "
              f"pred={row['mean_predicted']:.3f}  obs={row['observed_frequency']:.3f}")

    # --- ablations -----------------------------------------------------------
    print("\n=== ABLATIONS (what each component contributes) ===")
    ablations = {}

    # Rules-only proxy: the strongest single structural feature.
    for name in ("imsi_change_flag", "iccid_change_flag", "device_change_flag"):
        if name in features:
            col = features.index(name)
            pred = [1 if row[col] >= 1 else 0 for row in X_test]
            ablations[f"rule_only::{name}"] = metrics(y_test, pred)
            break

    iso = IsolationForest(n_estimators=200, contamination=0.05,
                          random_state=42, n_jobs=-1)
    iso.fit([x for x, label in zip(X_tr, y_tr) if label == 0])
    iso_scores = [-float(s) for s in iso.decision_function(X_test)]
    lo, hi = min(iso_scores), max(iso_scores)
    iso_prob = [(s - lo) / (hi - lo) if hi > lo else 0.0 for s in iso_scores]
    ablations["isolation_forest_only"] = {
        **metrics(y_test, [1 if p >= 0.5 else 0 for p in iso_prob]),
        "pr_auc_average_precision": average_precision(y_test, iso_prob)}
    ablations["random_forest_only"] = {
        "pr_auc_average_precision": final["pr_auc_average_precision"],
        "precision_fraud": final["precision_fraud"],
        "recall_fraud": final["recall_fraud"],
        "false_positive_rate": final["false_positive_rate"]}
    fused_prob = [0.7 * r + 0.3 * i for r, i in zip(test_prob, iso_prob)]
    ablations["fusion_rf_plus_iso"] = {
        **metrics(y_test, [1 if p >= best_t else 0 for p in fused_prob], fused_prob),
        "pr_auc_average_precision": average_precision(y_test, fused_prob)}

    for name, m in ablations.items():
        pr = m.get("pr_auc_average_precision", "—")
        print(f"  {name:28s} PR-AUC={pr}  precision={m.get('precision_fraud')}  "
              f"recall={m.get('recall_fraud')}  FPR={m.get('false_positive_rate')}")

    # --- adversarial / robustness -------------------------------------------
    print("\n=== ADVERSARIAL & ROBUSTNESS (end-to-end engine) ===")
    robustness = _robustness_suite()
    for case in robustness:
        status = "OK  " if case["acceptable"] else "FLAG"
        print(f"  {status} {case['name']:42s} {case['decision']:8s} "
              f"risk={case['risk']:5.1f}  {case['expectation']}")

    report = {
        "_disclaimer": (
            "ALL DATA AND OPERATOR SIGNALS ARE SYNTHETIC. The fraud base rate in "
            "this dataset (~74%) is not realistic; a production system sees <1%. "
            "These figures characterise a prototype and are NOT evidence of "
            "real-world performance. The model is NOT validated for deployment."),
        "methodology": {
            "split": {"train": len(X_tr), "threshold_tuning": len(X_tune),
                      "held_out_test": len(X_test)},
            "threshold_selected_on": "tuning split only",
            "held_out_used_for_tuning": False,
        },
        "held_out_test": final,
        "ablations": ablations,
        "robustness": robustness,
    }
    out = backend_path("data", "ml_evaluation_report.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"\nWrote {out}")
    print("\nREMINDER: synthetic data, unrealistic base rate, not validated for "
          "deployment.")
    return 0


def _robustness_suite():
    """
    End-to-end engine behaviour under adversarial and awkward conditions. Each
    case states what a DEFENSIBLE outcome looks like, so a regression that makes
    the system behave badly for legitimate users is visible.
    """
    from engine.detector import score_login
    from engine.profiles import load as load_profile

    KTM = {"lat": 27.7154, "lon": 85.3123}
    DELHI = {"lat": 28.6139, "lon": 77.2090}
    DOHA = {"lat": 25.2854, "lon": 51.5310}

    cases = [
        ("missing operator feed (no telecom flags)", "gita_newsim",
         {"current_location": KTM, "imei": "351234567890123",
          "logins_last_24h": 1, "failed_logins_last_24h": 0},
         lambda d: d in ("ALLOW", "MONITOR", "VERIFY"),
         "must still decide without operator signals"),
        ("spoofed browser location at victim's home", "sita_swapped",
         {"current_location": KTM, "imei": "999888777666555",
          "logins_last_24h": 5, "failed_logins_last_24h": 2,
          "imsi_change_flag": 1, "iccid_change_flag": 1,
          "sim_network_area": "Delhi", "otp_sim_gap_minutes": 3},
         lambda d: d == "BLOCK",
         "SIM history defeats a spoofed GPS fix"),
        ("legitimate traveller abroad", "bikash_migrant",
         {"current_location": DOHA, "imei": "356220011223344",
          "logins_last_24h": 1, "failed_logins_last_24h": 0},
         lambda d: d in ("ALLOW", "MONITOR"),
         "must NOT punish a migrant worker"),
        ("VPN / IP change only", "aarav_safe",
         {"current_location": KTM, "imei": "356938035643809",
          "logins_last_24h": 1, "failed_logins_last_24h": 0, "ip_change_flag": 1},
         lambda d: d in ("ALLOW", "MONITOR"),
         "an IP change alone is weak evidence"),
        ("lost phone, legitimate SIM replacement", "pratima_reissue",
         {"current_location": {"lat": 27.6766, "lon": 85.3250},
          "imei": "351778899001122", "logins_last_24h": 1,
          "failed_logins_last_24h": 0, "iccid_change_flag": 1},
         lambda d: d in ("MONITOR", "VERIFY"),
         "verify, but do not block a genuine reissue"),
        ("feature manipulation: impossible counters", "aarav_safe",
         {"current_location": KTM, "imei": "356938035643809",
          "logins_last_24h": 9999, "failed_logins_last_24h": 9999},
         lambda d: d in ("VERIFY", "BLOCK"),
         "absurd counters must not lower the score"),
        ("no location supplied at all", "aarav_safe",
         {"imei": "356938035643809", "logins_last_24h": 1,
          "failed_logins_last_24h": 0},
         lambda d: d in ("ALLOW", "MONITOR", "VERIFY"),
         "must not crash or auto-block"),
    ]

    out = []
    for name, profile_id, attempt, ok_fn, expectation in cases:
        profile = load_profile(profile_id)
        try:
            r = score_login(attempt, profile)
            decision, risk = r["decision"], r["risk_score"]
            acceptable = bool(ok_fn(decision))
        except Exception as e:                       # a crash is never acceptable
            decision, risk, acceptable = f"ERROR:{type(e).__name__}", -1.0, False
        out.append({"name": name, "profile": profile_id, "decision": decision,
                    "risk": risk, "acceptable": acceptable,
                    "expectation": expectation})
    return out


if __name__ == "__main__":
    sys.exit(main())

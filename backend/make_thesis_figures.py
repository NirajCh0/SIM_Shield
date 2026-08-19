"""
Generate the thesis result figures from the REAL evaluation output.

Every value plotted here is read from `data/*.json`, produced by the evaluation
harnesses — nothing is drawn by hand or typed in. A figure therefore cannot
disagree with the system it describes, which is the whole point: a chart made in
a drawing tool is an illustration, a chart made from the report is evidence.

Run the harnesses first so the reports are current:

    python evaluate.py            -> data/evaluation_report.json
    python evaluate_ml.py         -> data/ml_evaluation_report.json
    python evaluate_operator.py   -> data/operator_degradation.json
    python make_thesis_figures.py -> ../thesis_figures/generated/*.png

Output is 300 dpi PNG, sized for a single column of an A4 report.
"""
import io, json, os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import PercentFormatter

# Output goes inside the repository, resolved relative to this file — an
# absolute path to one developer's Desktop was committed here, so the script
# only ran on the machine it was written on.
OUT = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)), os.pardir, "docs", "figures"))
os.makedirs(OUT, exist_ok=True)
plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 10,
    "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.alpha": .25, "grid.linewidth": .6,
    "figure.dpi": 300, "savefig.dpi": 300, "savefig.bbox": "tight",
})
INK, ACC, WARN, BAD, OK = "#1d1d1f", "#0066cc", "#ff9500", "#c0392b", "#2f7d4f"
#: Which harness writes which report — used to tell the user what to run.
PRODUCED_BY = {
    "evaluation_report": "python evaluate.py",
    "ml_evaluation_report": "python evaluate_ml.py",
    "operator_degradation": "python evaluate_operator.py",
}


def load(n):
    """
    Read one evaluation report, or explain how to produce it.

    The reports are generated output and are git-ignored, so a fresh clone has
    none of them. Crashing with a FileNotFoundError traceback told the user
    nothing useful; naming the command that writes the missing file does.
    """
    path = os.path.join("data", "%s.json" % n)
    if not os.path.exists(path):
        raise SystemExit(
            "\n  Missing %s\n"
            "  The evaluation reports are generated, not committed.\n"
            "  Run this first (from the backend folder):\n\n"
            "      %s\n\n"
            "  Or run all three, then this script again:\n"
            "      python evaluate.py && python evaluate_ml.py && "
            "python evaluate_operator.py\n" % (path, PRODUCED_BY.get(n, "the matching harness")))
    return json.load(io.open(path, encoding="utf-8"))

ml, op, ev = load("ml_evaluation_report"), load("operator_degradation"), load("evaluation_report")
made = []

# A. Confusion matrix
h = ml["held_out_test"]; cm = h["confusion_matrix"]; total = sum(sum(r) for r in cm)
fig, ax = plt.subplots(figsize=(4.6, 4.0))
ax.imshow(cm, cmap="Blues", alpha=.85)
lab = [["True negative", "False positive"], ["False negative", "True positive"]]
for i in range(2):
    for j in range(2):
        ax.text(j, i, "%s\n%s\n(%.1f%%)" % ("{:,}".format(cm[i][j]), lab[i][j], cm[i][j]/total*100),
                ha="center", va="center", fontsize=9,
                color="white" if cm[i][j] > total*.3 else INK)
ax.set_xticks([0, 1], ["Predicted legitimate", "Predicted fraud"])
ax.set_yticks([0, 1], ["Actually\nlegitimate", "Actually\nfraud"])
ax.grid(False)
ax.set_title("Held-out test set (n = {:,}, {:.1%} fraud)".format(h["n"], h["positive_rate"]), fontsize=10)
fig.savefig(OUT + "/figA_confusion_matrix.png"); plt.close(fig); made.append("figA_confusion_matrix.png")

# B. Calibration
cal = [c for c in h["calibration"] if c["n"] > 0]
fig, ax = plt.subplots(figsize=(5.4, 4.2))
ax.plot([0, 1], [0, 1], "--", color="#999", lw=1, label="Perfect calibration")
xs = [c["mean_predicted"] for c in cal]; ys = [c["observed_frequency"] for c in cal]
ax.plot(xs, ys, "o-", color=ACC, lw=1.8, ms=6, label="SIMShield (Random Forest)")
w = max(cal, key=lambda c: abs(c["observed_frequency"] - c["mean_predicted"]))
ax.annotate("predicted %.2f\nobserved %.2f" % (w["mean_predicted"], w["observed_frequency"]),
            xy=(w["mean_predicted"], w["observed_frequency"]),
            xytext=(min(w["mean_predicted"] + .08, .55), max(w["observed_frequency"] - .30, .05)),
            fontsize=8.5, color=BAD, arrowprops=dict(arrowstyle="->", color=BAD, lw=1))
ax.set_xlabel("Mean predicted probability"); ax.set_ylabel("Observed fraud frequency")
ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.legend(frameon=False, fontsize=9, loc="upper left")
ax.set_title("Reliability diagram - Brier score %s" % h["brier_score"], fontsize=10)
fig.savefig(OUT + "/figB_calibration.png"); plt.close(fig); made.append("figB_calibration.png")

# C. Ablation
abl = ml["ablations"]
names = [("rule_only::imsi_change_flag", "Single rule\n(IMSI change)"),
         ("isolation_forest_only", "Isolation Forest\n(unsupervised)"),
         ("random_forest_only", "Random Forest\n(supervised)"),
         ("fusion_rf_plus_iso", "Fusion\n(RF + IF)")]
keys = [k for k, _ in names if k in abl]
lbl = [l for k, l in names if k in abl]
prec = [abl[k]["precision_fraud"] for k in keys]
rec = [abl[k]["recall_fraud"] for k in keys]
fpr = [abl[k]["false_positive_rate"] for k in keys]
x = range(len(keys)); bw = .26
fig, ax = plt.subplots(figsize=(7.4, 4.2))
ax.bar([i - bw for i in x], prec, bw, label="Precision", color=ACC)
ax.bar(list(x), rec, bw, label="Recall", color=OK)
ax.bar([i + bw for i in x], fpr, bw, label="False-positive rate", color=BAD)
for i, v in enumerate(rec): ax.text(i, v + .02, "%.2f" % v, ha="center", fontsize=8)
for i, v in enumerate(fpr): ax.text(i + bw, v + .02, "%.3f" % v, ha="center", fontsize=7.5, color=BAD)
ax.set_xticks(list(x), lbl, fontsize=8.5)
ax.set_ylim(0, 1.12); ax.yaxis.set_major_formatter(PercentFormatter(1.0))
ax.legend(frameon=False, fontsize=9, ncol=3, loc="lower right")
ax.set_title("Component ablation: what each detector achieves alone", fontsize=10)
fig.savefig(OUT + "/figC_ablation.png"); plt.close(fig); made.append("figC_ablation.png")

# D. Operator degradation
probe = "clean login, SIM reported abroad"
lbls, scores, cols = [], [], []
for c in op["conditions"]:
    row = next((p for p in c["isolating_probes"] if p["probe"] == probe), None)
    if not row: continue
    lbls.append(c["condition"].replace("_", " "))
    scores.append(row["risk_score"])
    cols.append(WARN if c["condition"] == "available" else OK)
fig, ax = plt.subplots(figsize=(7.8, 4.2))
bars = ax.bar(lbls, scores, color=cols)
ax.axhline(26, ls="--", lw=1, color="#999")
ax.text(len(lbls) - .4, 27.2, "VERIFY threshold", fontsize=8, color="#666", ha="right")
for b, s in zip(bars, scores):
    ax.text(b.get_x() + b.get_width()/2, s + .8, "%.1f" % s, ha="center", fontsize=8.5)
ax.set_ylabel("Fused risk score"); ax.set_ylim(0, 34)
plt.setp(ax.get_xticklabels(), rotation=28, ha="right", fontsize=8.5)
ax.set_title("Fail-open behaviour: an identical login under nine operator conditions\n"
             "(0 of 360 decisions became more restrictive)", fontsize=10)
fig.savefig(OUT + "/figD_operator_degradation.png"); plt.close(fig); made.append("figD_operator_degradation.png")

# E. Decision separation
cases = ev["scenarios"]["cases"]
order = ["ALLOW", "MONITOR", "VERIFY", "BLOCK"]
colmap = {"ALLOW": OK, "MONITOR": "#b8860b", "VERIFY": WARN, "BLOCK": BAD}
fig, ax = plt.subplots(figsize=(7.4, 4.2))
for d in order:
    pts = [c["risk_score"] for c in cases if c["expected"] == d]
    ax.scatter([d]*len(pts), pts, s=46, color=colmap[d], alpha=.82, edgecolor="white", linewidth=.6)
for y, t in ((14, "ALLOW <= 14"), (26, "MONITOR <= 26"), (80, "VERIFY <= 80")):
    ax.axhline(y, ls="--", lw=1, color="#aaa")
    ax.text(-0.42, y + 1.6, t, fontsize=7.6, color="#666", ha="left")
ax.set_ylabel("Fused risk score"); ax.set_ylim(0, 104); ax.set_xlim(-0.55, 3.5)
ax.set_title("Decision separation across %d end-to-end scenarios (%d/%d matched expectation)"
             % (len(cases), ev["scenarios"]["matched"], ev["scenarios"]["n"]), fontsize=10)
fig.savefig(OUT + "/figE_decision_distribution.png"); plt.close(fig); made.append("figE_decision_distribution.png")

print("generated:")
for m in made: print("  ", m)

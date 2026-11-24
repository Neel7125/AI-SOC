"""Generate all ML evaluation artefacts into results/ml_evaluation/ from saved models and the held-out test split."""
from __future__ import annotations

import json
import logging

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import config
from evaluation import confusion_matrix as cm_plot
from evaluation import feature_analysis as fa
from evaluation import roc_pr_curves as rp
from evaluation.classification_metrics import binary_metrics, multiclass_metrics, report_df
from ml_engine import model_registry as reg
from ml_engine.preprocessing import prepare
from ml_engine.train import ALGORITHMS

log = logging.getLogger(__name__)


def run_ml_evaluation(dataset: str | None = None) -> dict:
    out = config.ML_EVAL_DIR
    sp = prepare(dataset, save=False)
    classes, bi = list(sp.encoder.classes_), sp.benign_idx
    yb = (sp.y_test != bi).astype(int)
    results, scores, reports, probas = {}, {}, [], {}
    for name in ALGORITHMS:
        if not (config.MODELS_DIR / f"{name}.joblib").exists():
            continue
        m = reg.load_model(name)
        proba = m.predict_proba(sp.X_test)
        pm = 1 - proba[:, bi]
        pred = proba.argmax(1)
        results[name] = {"binary": binary_metrics(yb, (pm >= config.ML_THRESHOLD).astype(int), pm),
                         "multiclass": multiclass_metrics(sp.y_test, pred, classes)}
        scores[name], probas[name] = pm, proba
        r = report_df(sp.y_test, pred, classes); r.insert(0, "model", name); reports.append(r)
    best = reg.best_name()
    iso = reg.load_anomaly()
    a_sc = iso.score(sp.X_test)
    results["isolation_forest"] = {"binary": binary_metrics(yb, iso.is_anomaly(a_sc).astype(int), a_sc),
                                   "note": "unsupervised anomaly detector; threshold = benign-train percentile %.1f" % iso.threshold_pct}
    scores["isolation_forest (anomaly score)"] = a_sc

    bp = probas[best]; pred_b = bp.argmax(1)
    cm_plot.plot_cm(yb, (1 - bp[:, bi] >= config.ML_THRESHOLD).astype(int), ["Benign", "Malicious"], out / "confusion_matrix.png", f"Binary confusion matrix - {best}")
    cm_plot.plot_cm(yb, (1 - bp[:, bi] >= config.ML_THRESHOLD).astype(int), ["Benign", "Malicious"], out / "normalized_confusion_matrix.png", f"Normalised confusion matrix - {best}", True)
    cm_plot.plot_cm(sp.y_test, pred_b, classes, out / "multiclass_confusion_matrix.png", f"Multiclass confusion matrix - {best}")
    cm_plot.plot_cm(sp.y_test, pred_b, classes, out / "multiclass_normalized_confusion_matrix.png", f"Multiclass normalised - {best}", True)
    rp.plot_roc(yb, scores, out / "roc_curve.png")
    rp.plot_pr(yb, scores, out / "precision_recall_curve.png")
    fa.plot_importance(reg.load_model(best).feature_importance(), out / "feature_importance.png", f"Feature importance - {best}")
    fa.plot_correlation(sp.X_train, out / "feature_correlation.png")
    fa.plot_model_comparison(pd.DataFrame({k: v["binary"] for k, v in results.items() if k != "isolation_forest"}).T, out / "model_comparison.png")
    try:
        fa.plot_learning_curve(ALGORITHMS[best]().build(len(classes)) if best != "xgboost" else ALGORITHMS["random_forest"]().build(len(classes)),
                               sp.X_train, sp.y_train, out / "learning_curve.png", f"Learning curve ({best if best != 'xgboost' else 'random_forest'})")
    except Exception as exc:  # noqa: BLE001
        log.warning("learning curve skipped: %s", exc)
    fig, ax = plt.subplots(figsize=(6.5, 4))
    ax.hist(a_sc[yb == 0], bins=40, alpha=.6, label="benign"); ax.hist(a_sc[yb == 1], bins=40, alpha=.6, label="malicious")
    ax.axvline(iso.threshold_pct, color="r", ls="--", label="anomaly threshold")
    ax.set_xlabel("Isolation Forest anomaly score (percentile vs benign)"); ax.set_ylabel("Flows"); ax.legend()
    ax.set_title("Anomaly score distribution (test set)"); plt.tight_layout(); fig.savefig(out / "anomaly_scores.png", dpi=130); plt.close(fig)

    pd.concat(reports).to_csv(out / "classification_report.csv")
    payload = {"dataset": sp.pre.dataset, "best_model": best, "test_rows": int(len(yb)), "classes": classes,
               "test_class_counts": {classes[i]: int((sp.y_test == i).sum()) for i in range(len(classes))},
               "note": "All values computed from held-out test-set predictions of SYNTHETIC data unless a real dataset is configured.",
               "metrics": results}
    (out / "evaluation_metrics.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload

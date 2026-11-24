"""ROC and Precision-Recall curves."""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import average_precision_score, precision_recall_curve, roc_auc_score, roc_curve


def plot_roc(y_true, scores: dict, path) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    for name, s in scores.items():
        fpr, tpr, _ = roc_curve(y_true, s)
        ax.plot(fpr, tpr, label=f"{name} (AUC={roc_auc_score(y_true, s):.3f})")
    ax.plot([0, 1], [0, 1], "k--", lw=.8); ax.set_xlabel("False Positive Rate"); ax.set_ylabel("True Positive Rate")
    ax.set_title("ROC curve (binary: malicious vs benign, test set)"); ax.legend(loc="lower right"); plt.tight_layout()
    fig.savefig(path, dpi=130); plt.close(fig)


def plot_pr(y_true, scores: dict, path) -> None:
    fig, ax = plt.subplots(figsize=(6, 5))
    for name, s in scores.items():
        p, r, _ = precision_recall_curve(y_true, s)
        ax.plot(r, p, label=f"{name} (AP={average_precision_score(y_true, s):.3f})")
    ax.axhline(y_true.mean(), color="k", ls="--", lw=.8, label="prevalence")
    ax.set_xlabel("Recall"); ax.set_ylabel("Precision"); ax.set_title("Precision-Recall curve (test set)")
    ax.legend(loc="lower left"); plt.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)

"""Confusion-matrix plots."""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from sklearn.metrics import confusion_matrix


def plot_cm(y_true, y_pred, labels: list[str], path, title: str, normalize: bool = False) -> None:
    cm = confusion_matrix(y_true, y_pred, labels=list(range(len(labels))))
    data = cm.astype(float)
    if normalize:
        data = data / np.maximum(data.sum(axis=1, keepdims=True), 1)
    n = len(labels)
    fig, ax = plt.subplots(figsize=(max(4.5, n * 1.1), max(4, n * 0.95)))
    sns.heatmap(data, annot=True, fmt=".2f" if normalize else ".0f", cmap="Blues", xticklabels=labels, yticklabels=labels, ax=ax, cbar=False)
    ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(title)
    plt.xticks(rotation=30, ha="right"); plt.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)

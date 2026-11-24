"""Feature importance, correlation heatmap, learning curve."""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from sklearn.model_selection import learning_curve


def plot_importance(imp: pd.Series, path, title: str, top: int = 15) -> None:
    s = imp.head(top)[::-1]
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.barh(s.index, s.values, color="#2a9d8f"); ax.set_title(title); ax.set_xlabel("Importance")
    plt.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_correlation(X: pd.DataFrame, path) -> None:
    fig, ax = plt.subplots(figsize=(9, 7.5))
    sns.heatmap(X.corr(), cmap="coolwarm", center=0, ax=ax, annot=False)
    ax.set_title("Feature correlation (training split)"); plt.tight_layout(); fig.savefig(path, dpi=130); plt.close(fig)


def plot_learning_curve(estimator, X, y, path, title: str) -> None:
    sizes, tr, va = learning_curve(estimator, X, y, cv=3, train_sizes=np.linspace(.1, 1, 5), scoring="f1_macro", n_jobs=-1, random_state=42,
                                   shuffle=True)
    fig, ax = plt.subplots(figsize=(6, 4.5))
    ax.plot(sizes, tr.mean(1), "o-", label="train"); ax.plot(sizes, va.mean(1), "o-", label="cross-val")
    ax.fill_between(sizes, va.mean(1) - va.std(1), va.mean(1) + va.std(1), alpha=.2)
    ax.set_xlabel("Training samples"); ax.set_ylabel("Macro F1"); ax.set_title(title); ax.legend(); plt.tight_layout()
    fig.savefig(path, dpi=130); plt.close(fig)


def plot_model_comparison(df: pd.DataFrame, path) -> None:
    cols = ["precision", "recall", "f1", "balanced_accuracy", "mcc"]
    ax = df[cols].plot(kind="bar", figsize=(8, 4.5), width=.8)
    ax.set_ylim(0, 1.05); ax.set_title("Model comparison (binary detection, test set)"); ax.set_ylabel("Score")
    plt.xticks(rotation=0); plt.legend(loc="lower right", ncol=3); plt.tight_layout(); plt.savefig(path, dpi=130); plt.close()

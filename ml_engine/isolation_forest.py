"""Isolation Forest anomaly detector.

anomaly_score (0-100) = percentile rank of the raw isolation score among BENIGN training records.
It measures *unusualness vs. normal traffic* - it is NOT a probability of maliciousness.
"""
from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def _slog(X):
    X = np.asarray(X, dtype=float)
    return np.sign(X) * np.log1p(np.abs(X))


class IsolationForestModel:
    name = "isolation_forest"

    def __init__(self, n_estimators: int = 200, threshold_pct: float = 97.0, seed: int = 42):
        self.n_estimators, self.threshold_pct, self.seed = n_estimators, threshold_pct, seed
        self.est: IsolationForest | None = None
        self.feature_names: list[str] = []

    def fit(self, X_benign: pd.DataFrame) -> "IsolationForestModel":
        self.feature_names = list(X_benign.columns)
        Z = _slog(X_benign)
        self.mu, self.sd = Z.mean(axis=0), Z.std(axis=0) + 1e-9
        self.est = IsolationForest(n_estimators=self.n_estimators, contamination="auto", random_state=self.seed, n_jobs=-1).fit(Z)
        self.ref = np.sort(-self.est.score_samples(Z))
        return self

    def raw(self, X: pd.DataFrame) -> np.ndarray:
        return -self.est.score_samples(_slog(X[self.feature_names]))

    def score(self, X: pd.DataFrame) -> np.ndarray:
        return 100.0 * np.searchsorted(self.ref, self.raw(X), side="right") / len(self.ref)

    def is_anomaly(self, scores: np.ndarray) -> np.ndarray:
        return scores >= self.threshold_pct

    def explain(self, row: pd.Series, top: int = 3) -> list[str]:
        z = (_slog(row[self.feature_names].to_frame().T)[0] - self.mu) / self.sd
        idx = np.argsort(-np.abs(z))[:top]
        return [f"{self.feature_names[i]} is {abs(z[i]):.1f} std-dev {'above' if z[i] > 0 else 'below'} the benign baseline (log scale)" for i in idx]

    def save(self, path: Path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path) -> "IsolationForestModel":
        return joblib.load(path)

"""Common model interface so new algorithms can be plugged in."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


class BaseModel(ABC):
    name: str = "base"

    @abstractmethod
    def build(self, n_classes: int):
        """Return an unfitted estimator exposing fit/predict_proba."""

    def __init__(self):
        self.est = None
        self.feature_names: list[str] = []

    def fit(self, X: pd.DataFrame, y: np.ndarray) -> "BaseModel":
        self.feature_names = list(X.columns)
        self.est = self.build(len(np.unique(y)))
        self.est.fit(X, y)
        return self

    def predict_proba(self, X: pd.DataFrame) -> np.ndarray:
        return self.est.predict_proba(X[self.feature_names])

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return self.predict_proba(X).argmax(axis=1)

    @abstractmethod
    def feature_importance(self) -> pd.Series:
        ...

    def params(self) -> dict:
        return {}

    def save(self, path: Path) -> None:
        joblib.dump(self, path)

    @staticmethod
    def load(path: Path) -> "BaseModel":
        return joblib.load(path)

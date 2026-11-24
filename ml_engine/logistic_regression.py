from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from ml_engine.base import BaseModel


def _signed_log(X):
    X = np.asarray(X, dtype=float)
    return np.sign(X) * np.log1p(np.abs(X))      # tames heavy-tailed flow features before scaling


class LogisticRegressionModel(BaseModel):
    name = "logistic_regression"
    PARAMS = dict(max_iter=2000, C=1.0, class_weight="balanced", random_state=42)

    def build(self, n_classes):
        return Pipeline([("log", FunctionTransformer(_signed_log)), ("scale", StandardScaler()),
                         ("clf", LogisticRegression(**self.PARAMS))])

    def feature_importance(self) -> pd.Series:
        coef = np.abs(self.est.named_steps["clf"].coef_).mean(axis=0)
        return pd.Series(coef, index=self.feature_names).sort_values(ascending=False)

    def params(self):
        return dict(self.PARAMS)

from __future__ import annotations

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from ml_engine.base import BaseModel


class RandomForestModel(BaseModel):
    name = "random_forest"
    PARAMS = dict(n_estimators=200, max_depth=None, min_samples_leaf=2, class_weight="balanced_subsample", n_jobs=-1, random_state=42)

    def build(self, n_classes):
        return RandomForestClassifier(**self.PARAMS)

    def feature_importance(self) -> pd.Series:
        return pd.Series(self.est.feature_importances_, index=self.feature_names).sort_values(ascending=False)

    def params(self):
        return dict(self.PARAMS)

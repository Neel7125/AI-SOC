from __future__ import annotations

import pandas as pd

from ml_engine.base import BaseModel


class XGBoostModel(BaseModel):
    name = "xgboost"
    PARAMS = dict(n_estimators=250, max_depth=6, learning_rate=0.1, subsample=0.9, colsample_bytree=0.9,
                  tree_method="hist", eval_metric="mlogloss", random_state=42, n_jobs=-1)

    def build(self, n_classes):
        from xgboost import XGBClassifier
        return XGBClassifier(objective="multi:softprob", num_class=n_classes, **self.PARAMS)

    def feature_importance(self) -> pd.Series:
        return pd.Series(self.est.feature_importances_, index=self.feature_names).sort_values(ascending=False)

    def params(self):
        return dict(self.PARAMS)

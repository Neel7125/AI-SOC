"""Inference only: loads persisted models; never trains."""
from __future__ import annotations

import numpy as np
import pandas as pd

import config
from ml_engine import model_registry as reg
from ml_engine.preprocessing import Preprocessor


class Predictor:
    def __init__(self, model_name: str | None = None):
        self.pre = Preprocessor.load()
        self.name = model_name or reg.best_name()
        self.model = reg.load_model(self.name)
        self.iso = reg.load_anomaly()
        self.classes = self.pre.classes
        self.benign_idx = self.classes.index(self.pre.benign_label)

    def predict_flows(self, df: pd.DataFrame, explain: bool = True) -> pd.DataFrame:
        X = self.pre.transform(df)
        proba = self.model.predict_proba(X)
        idx = proba.argmax(axis=1)
        out = pd.DataFrame(index=df.index)
        out["ml_model"] = self.name
        out["ml_category"] = [self.classes[i] for i in idx]
        out["ml_prob_malicious"] = 1.0 - proba[:, self.benign_idx]      # probability of ANY attack class
        out["ml_confidence"] = proba[np.arange(len(idx)), idx]           # confidence of the predicted class
        out["ml_is_malicious"] = (out["ml_prob_malicious"] >= config.ML_THRESHOLD).astype(int)
        sc = self.iso.score(X)
        out["anomaly_score"] = sc                                        # unusualness vs. benign baseline (NOT malicious probability)
        out["is_anomaly"] = self.iso.is_anomaly(sc).astype(int)
        out["anomaly_reason"] = ""
        if explain:
            for i in np.where(out["is_anomaly"].values == 1)[0]:
                out.iloc[i, out.columns.get_loc("anomaly_reason")] = "; ".join(self.iso.explain(X.iloc[i]))
        return out

    def predict_one(self, features: dict) -> dict:
        r = self.predict_flows(pd.DataFrame([features]))
        return r.iloc[0].to_dict()

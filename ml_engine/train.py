"""Model training (kept separate from inference). Retraining = re-running this module."""
from __future__ import annotations

import logging
import time

import numpy as np

import config
from evaluation.classification_metrics import binary_metrics, multiclass_metrics
from ml_engine import model_registry as reg
from ml_engine.isolation_forest import IsolationForestModel
from ml_engine.logistic_regression import LogisticRegressionModel
from ml_engine.preprocessing import Splits, apply_smote, prepare
from ml_engine.random_forest import RandomForestModel
from ml_engine.xgboost_model import XGBoostModel

log = logging.getLogger(__name__)
ALGORITHMS = {"random_forest": RandomForestModel, "xgboost": XGBoostModel, "logistic_regression": LogisticRegressionModel}


def p_malicious(proba: np.ndarray, benign_idx: int) -> np.ndarray:
    return 1.0 - proba[:, benign_idx]


def eval_split(model, X, y, benign_idx: int, classes: list[str]) -> dict:
    proba = model.predict_proba(X)
    pred = proba.argmax(axis=1)
    pm = p_malicious(proba, benign_idx)
    yb, pb = (y != benign_idx).astype(int), (pm >= config.ML_THRESHOLD).astype(int)
    return {"binary": binary_metrics(yb, pb, pm), "multiclass": multiclass_metrics(y, pred, classes)}


def train_all(dataset: str | None = None, use_smote: bool = False, only: list[str] | None = None) -> dict:
    sp: Splits = prepare(dataset)
    classes, bi = list(sp.encoder.classes_), sp.benign_idx
    X_tr, y_tr = sp.X_train, sp.y_train
    if use_smote:
        X_tr, y_tr = apply_smote(X_tr, y_tr)          # training split only
        log.info("SMOTE applied to training split: %d rows", len(y_tr))
    summary = {}
    for name, cls in ALGORITHMS.items():
        if only and name not in only:
            continue
        t0 = time.time()
        m = cls().fit(X_tr, y_tr)
        secs = time.time() - t0
        val, test = eval_split(m, sp.X_val, sp.y_val, bi, classes), eval_split(m, sp.X_test, sp.y_test, bi, classes)
        m.save(config.MODELS_DIR / f"{name}.joblib")
        reg.register(name, {"dataset": sp.pre.dataset, "classes": classes, "benign_label": sp.pre.benign_label,
                            "features": sp.pre.feature_names, "train_rows": int(len(y_tr)), "val_rows": int(len(sp.y_val)),
                            "test_rows": int(len(sp.y_test)), "smote": use_smote, "hyperparameters": m.params(),
                            "split": "stratified 70/15/15, seed 42", "train_seconds": round(secs, 2),
                            "validation": val, "test": test})
        summary[name] = {"val_macro_f1": val["multiclass"]["macro_f1"], "test_macro_f1": test["multiclass"]["macro_f1"]}
        log.info("%s trained in %.1fs | val macroF1=%.4f", name, secs, val["multiclass"]["macro_f1"])
    if summary:
        best = max(summary, key=lambda k: summary[k]["val_macro_f1"])   # selected on VALIDATION, reported on TEST
        reg.set_best(best); summary["best"] = best
    # Anomaly detector: trained on BENIGN training records only (unsupervised)
    iso = IsolationForestModel().fit(sp.X_train[sp.y_train == bi])
    iso.save(config.MODELS_DIR / "isolation_forest.joblib")
    sc = iso.score(sp.X_test)
    yb = (sp.y_test != bi).astype(int)
    reg.register("isolation_forest", {"dataset": sp.pre.dataset, "features": sp.pre.feature_names, "threshold_percentile": iso.threshold_pct,
                                      "hyperparameters": {"n_estimators": iso.n_estimators}, "trained_on": "benign training records only",
                                      "test": {"binary": binary_metrics(yb, iso.is_anomaly(sc).astype(int), sc)}})
    summary["isolation_forest_auc"] = reg.get_registry()["models"]["isolation_forest"]["test"]["binary"].get("auc_roc")
    return summary

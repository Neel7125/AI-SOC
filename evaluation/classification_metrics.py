"""Classification metrics computed from actual predictions (never hand-entered)."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import (accuracy_score, average_precision_score, balanced_accuracy_score, cohen_kappa_score,
                             confusion_matrix, f1_score, matthews_corrcoef, precision_score, recall_score,
                             roc_auc_score, classification_report)


def _div(a, b):
    return float(a / b) if b else 0.0


def binary_metrics(y_true, y_pred, y_score=None) -> dict:
    y_true, y_pred = np.asarray(y_true).astype(int), np.asarray(y_pred).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    m = {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
         "accuracy": accuracy_score(y_true, y_pred),
         "precision": precision_score(y_true, y_pred, zero_division=0),
         "recall": recall_score(y_true, y_pred, zero_division=0),
         "f1": f1_score(y_true, y_pred, zero_division=0),
         "macro_f1": f1_score(y_true, y_pred, average="macro", zero_division=0),
         "weighted_f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
         "specificity": _div(tn, tn + fp), "false_positive_rate": _div(fp, fp + tn), "false_negative_rate": _div(fn, fn + tp),
         "negative_predictive_value": _div(tn, tn + fn),
         "balanced_accuracy": balanced_accuracy_score(y_true, y_pred),
         "mcc": matthews_corrcoef(y_true, y_pred), "cohen_kappa": cohen_kappa_score(y_true, y_pred)}
    if y_score is not None and len(np.unique(y_true)) == 2:
        m["auc_roc"] = roc_auc_score(y_true, y_score)
        m["auc_pr"] = average_precision_score(y_true, y_score)
    return {k: (round(float(v), 5) if isinstance(v, (float, np.floating)) else v) for k, v in m.items()}


def multiclass_metrics(y_true, y_pred, class_names: list[str]) -> dict:
    m = {"accuracy": accuracy_score(y_true, y_pred), "macro_precision": precision_score(y_true, y_pred, average="macro", zero_division=0),
         "macro_recall": recall_score(y_true, y_pred, average="macro", zero_division=0),
         "macro_f1": f1_score(y_true, y_pred, average="macro", zero_division=0),
         "weighted_f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
         "balanced_accuracy": balanced_accuracy_score(y_true, y_pred), "mcc": matthews_corrcoef(y_true, y_pred),
         "cohen_kappa": cohen_kappa_score(y_true, y_pred)}
    return {k: round(float(v), 5) for k, v in m.items()}


def report_df(y_true, y_pred, class_names: list[str]) -> pd.DataFrame:
    rep = classification_report(y_true, y_pred, labels=list(range(len(class_names))), target_names=class_names, output_dict=True, zero_division=0)
    return pd.DataFrame(rep).T.round(4)

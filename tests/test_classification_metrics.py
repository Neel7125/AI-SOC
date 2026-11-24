"""Unit tests for evaluation.classification_metrics."""
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.classification_metrics import binary_metrics, multiclass_metrics, report_df


CLASSES = ["BENIGN", "DoS", "PortScan", "BruteForce"]


class TestBinaryMetrics:
    def test_perfect_classifier(self):
        y = np.array([0, 0, 1, 1, 1])
        m = binary_metrics(y, y)
        assert m["accuracy"] == 1.0
        assert m["precision"] == 1.0
        assert m["recall"] == 1.0
        assert m["f1"] == 1.0
        assert m["fp"] == 0
        assert m["fn"] == 0

    def test_all_wrong(self):
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([1, 1, 0, 0])
        m = binary_metrics(y_true, y_pred)
        assert m["accuracy"] == 0.0
        assert m["recall"] == 0.0

    def test_all_predicted_positive(self):
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([1, 1, 1, 1])
        m = binary_metrics(y_true, y_pred)
        assert m["recall"] == 1.0
        assert m["false_positive_rate"] == 1.0

    def test_all_predicted_negative(self):
        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([0, 0, 0, 0])
        m = binary_metrics(y_true, y_pred)
        assert m["recall"] == 0.0
        assert m["false_positive_rate"] == 0.0

    def test_expected_keys_present(self):
        y = np.array([0, 1, 0, 1])
        m = binary_metrics(y, y)
        for k in ("tp", "fp", "tn", "fn", "accuracy", "precision", "recall", "f1",
                  "specificity", "false_positive_rate", "false_negative_rate",
                  "balanced_accuracy", "mcc", "cohen_kappa"):
            assert k in m, f"missing key: {k}"

    def test_auc_included_when_scores_given(self):
        y_true = np.array([0, 0, 1, 1])
        scores = np.array([0.1, 0.2, 0.8, 0.9])
        m = binary_metrics(y_true, (scores >= 0.5).astype(int), scores)
        assert "auc_roc" in m
        assert "auc_pr" in m
        assert 0.0 <= m["auc_roc"] <= 1.0

    def test_all_values_rounded_to_5dp(self):
        y = np.array([0, 1, 1, 0, 1])
        m = binary_metrics(y, np.array([0, 1, 0, 0, 1]))
        for v in m.values():
            if isinstance(v, float):
                assert len(str(v).split(".")[-1]) <= 5

    def test_fpr_fpr_complement_of_specificity(self):
        y_true = np.array([0, 0, 0, 1, 1])
        y_pred = np.array([0, 1, 0, 1, 0])
        m = binary_metrics(y_true, y_pred)
        assert abs(m["false_positive_rate"] + m["specificity"] - 1.0) < 1e-9


class TestMulticlassMetrics:
    def test_perfect(self):
        y = np.array([0, 1, 2, 3])
        m = multiclass_metrics(y, y, CLASSES)
        assert m["accuracy"] == 1.0
        assert m["macro_f1"] == 1.0

    def test_expected_keys(self):
        y = np.array([0, 1, 2, 3])
        m = multiclass_metrics(y, y, CLASSES)
        for k in ("accuracy", "macro_precision", "macro_recall", "macro_f1",
                  "weighted_f1", "balanced_accuracy", "mcc", "cohen_kappa"):
            assert k in m

    def test_all_wrong(self):
        y_true = np.array([0, 1, 2, 3])
        y_pred = np.array([1, 2, 3, 0])
        m = multiclass_metrics(y_true, y_pred, CLASSES)
        assert m["accuracy"] == 0.0

    def test_values_are_rounded_floats(self):
        y = np.array([0, 1, 2, 3, 0, 1])
        m = multiclass_metrics(y, y, CLASSES)
        for v in m.values():
            assert isinstance(v, float)


class TestReportDf:
    def test_shape(self):
        y = np.array([0, 1, 2, 3, 0, 1, 2, 3])
        df = report_df(y, y, CLASSES)
        # rows = classes + accuracy + macro avg + weighted avg
        assert df.shape[0] >= len(CLASSES)

    def test_has_precision_column(self):
        y = np.array([0, 1, 2, 0, 1, 2])
        df = report_df(y, y, CLASSES[:3])
        assert "precision" in df.columns

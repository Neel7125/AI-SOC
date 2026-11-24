"""Unit tests for evaluation.soc_metrics."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.soc_metrics import soc_metrics, simulate_queue


def _alerts_df(n=10, all_tp=True, include_times=True) -> pd.DataFrame:
    base = pd.Timestamp("2024-01-01 08:00:00")
    rows = []
    for i in range(n):
        created = base + pd.Timedelta(minutes=i * 5)
        detected = created + pd.Timedelta(minutes=1)
        acked = detected + pd.Timedelta(minutes=10) if include_times else pd.NaT
        responded = acked + pd.Timedelta(minutes=20) if include_times and pd.notna(acked) else pd.NaT
        rows.append({"alert_id": f"ALT-{i:04d}", "created_at": created, "detected_at": detected,
                     "acknowledged_at": acked, "responded_at": responded,
                     "risk_level": "High", "risk_score": 70.0, "gt_label": int(all_tp)})
    return pd.DataFrame(rows)


class TestSocMetrics:
    def test_empty_df(self):
        m = soc_metrics(pd.DataFrame())
        assert m == {"alert_volume": 0}

    def test_alert_volume(self):
        m = soc_metrics(_alerts_df(n=7))
        assert m["alert_volume"] == 7

    def test_mttd_positive(self):
        m = soc_metrics(_alerts_df())
        assert m.get("MTTD_min") is not None
        assert m["MTTD_min"] > 0

    def test_mtta_positive(self):
        m = soc_metrics(_alerts_df())
        assert m.get("MTTA_min") is not None
        assert m["MTTA_min"] > 0

    def test_all_true_positives(self):
        m = soc_metrics(_alerts_df(all_tp=True))
        assert m["alerts_false_positive"] == 0
        assert m["alert_precision"] == 1.0

    def test_all_false_positives(self):
        m = soc_metrics(_alerts_df(all_tp=False))
        assert m["alerts_true_positive"] == 0
        assert m["alert_precision"] == 0.0

    def test_missing_timestamps_excluded_not_imputed(self):
        df = _alerts_df(include_times=False)
        m = soc_metrics(df)
        # With no ack timestamps MTTA should be None (not imputed)
        assert m.get("MTTA_min") is None

    def test_sla_compliance_all_within_sla(self):
        """All ack times are 10 min, default SLA is 15 min -> should be 1.0."""
        m = soc_metrics(_alerts_df())
        assert m.get("sla_ack_compliance") == 1.0

    def test_sla_compliance_all_outside_sla(self):
        df = _alerts_df()
        # Push acked_at way beyond SLA
        df["acknowledged_at"] = df["detected_at"] + pd.Timedelta(hours=2)
        m = soc_metrics(df)
        assert m.get("sla_ack_compliance") == 0.0


class TestSimulateQueue:
    def _detect_times(self, n=5) -> pd.Series:
        base = pd.Timestamp("2024-01-01 09:00:00")
        return pd.Series([base + pd.Timedelta(minutes=i * 3) for i in range(n)])

    def test_output_shape(self):
        t = self._detect_times()
        q = simulate_queue(t, None)
        assert len(q) == len(t)
        assert "acknowledged_at" in q.columns
        assert "responded_at" in q.columns

    def test_acknowledged_at_after_detected_at(self):
        t = self._detect_times()
        q = simulate_queue(t, None)
        assert (q["acknowledged_at"] >= t.values).all()

    def test_responded_at_after_acknowledged(self):
        t = self._detect_times()
        q = simulate_queue(t, None)
        assert (q["responded_at"] >= q["acknowledged_at"]).all()

    def test_priority_queue_handles_scores(self):
        t = self._detect_times(10)
        pri = pd.Series(np.random.rand(10) * 100)
        q = simulate_queue(t, pri)
        assert len(q) == 10

    def test_time_factor_reduces_duration(self):
        t = self._detect_times()
        q_full = simulate_queue(t, None, time_factor=1.0)
        q_fast = simulate_queue(t, None, time_factor=0.5)
        # With a faster time factor, all ack times should be <= full time factor
        assert (q_fast["acknowledged_at"] <= q_full["acknowledged_at"]).all()

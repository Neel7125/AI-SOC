"""SOC operational metrics + analyst-queue simulation.

Timestamps used here are either RECORDED (analyst actions in the dashboard) or SIMULATED (analyst-queue model).
Rows with missing timestamps are excluded - nothing is imputed. The simulation parameters are ASSUMPTIONS (config.SOC_SIM).
"""
from __future__ import annotations

import heapq

import numpy as np
import pandas as pd

import config


def simulate_queue(detect_times: pd.Series, priority: pd.Series | None, n_analysts: int | None = None, triage_min: float | None = None,
                   time_factor: float = 1.0, response_min: float | None = None) -> pd.DataFrame:
    """Discrete-event model: analysts pull the highest-priority (or FIFO if priority None) detected alert when free."""
    sim = config.SOC_SIM
    n_analysts = n_analysts or sim["analysts"]
    dur = pd.Timedelta(minutes=(triage_min or sim["triage_minutes"]) * time_factor)
    resp = pd.Timedelta(minutes=response_min if response_min is not None else sim["response_minutes"])
    n = len(detect_times)
    order = np.argsort(detect_times.values, kind="stable")
    det = detect_times.values[order]
    pri = (priority.values[order] if priority is not None else np.zeros(n))
    free = [pd.Timestamp(det[0])] * n_analysts if n else []
    heapq.heapify(free)
    pending: list = []   # (-priority, detect, idx)
    ack = [None] * n
    i = 0
    done = 0
    while done < n:
        t = heapq.heappop(free)
        if not pending and i < n and pd.Timestamp(det[i]) > t:
            t = pd.Timestamp(det[i])
        while i < n and pd.Timestamp(det[i]) <= t:
            heapq.heappush(pending, (-float(pri[i]) if priority is not None else 0.0, det[i], i)); i += 1
        _, _, k = heapq.heappop(pending)
        ack[k] = t
        heapq.heappush(free, t + dur)
        done += 1
    out = pd.DataFrame(index=detect_times.index[order])
    out["acknowledged_at"] = pd.to_datetime(ack)
    out["responded_at"] = out["acknowledged_at"] + dur + resp
    out["investigation_minutes"] = dur.total_seconds() / 60
    return out.reindex(detect_times.index)


def _mean_min(a: pd.Series, b: pd.Series) -> float | None:
    d = (pd.to_datetime(b) - pd.to_datetime(a)).dt.total_seconds().dropna() / 60
    return None if d.empty else round(float(d.mean()), 3)


def soc_metrics(alerts: pd.DataFrame, llm_latency_s: float | None = None) -> dict:
    """MTTD/MTTA/MTTR etc. from alert timestamps; only rows where both timestamps exist contribute."""
    if alerts.empty:
        return {"alert_volume": 0}
    a = alerts.copy()
    sim = config.SOC_SIM
    mttd = _mean_min(a["created_at"], a["detected_at"])
    mtta = _mean_min(a["detected_at"], a["acknowledged_at"])
    mttr = _mean_min(a["detected_at"], a["responded_at"])
    ack_d = (pd.to_datetime(a["acknowledged_at"]) - pd.to_datetime(a["detected_at"])).dt.total_seconds() / 60
    resp_d = (pd.to_datetime(a["responded_at"]) - pd.to_datetime(a["detected_at"])).dt.total_seconds() / 60
    gt = a["gt_label"].dropna()
    tp = int((a["gt_label"] == 1).sum()); fp = int((a["gt_label"] == 0).sum())
    return {"alert_volume": int(len(a)), "MTTD_min": mttd, "MTTA_min": mtta, "MTTR_min": mttr,
            "sla_ack_compliance": None if ack_d.dropna().empty else round(float((ack_d.dropna() <= sim["ack_sla_minutes"]).mean()), 4),
            "sla_response_compliance": None if resp_d.dropna().empty else round(float((resp_d.dropna() <= sim["respond_sla_minutes"]).mean()), 4),
            "alerts_true_positive": tp, "alerts_false_positive": fp,
            "alert_precision": None if gt.empty else round(tp / max(tp + fp, 1), 4),
            "avg_investigation_minutes": None if a["acknowledged_at"].isna().all() else round(float(((pd.to_datetime(a["responded_at"]) - pd.to_datetime(a["acknowledged_at"])).dt.total_seconds() / 60 - sim["response_minutes"]).dropna().mean()), 3),
            "avg_llm_response_s": llm_latency_s,
            "timestamp_basis": "simulated analyst queue unless statuses were changed by analysts (recorded)"}

"""Scoring of events and conversion into analyst-facing alerts (incidents).

Event-level decisions for the four SOC configurations (flows):
  A traditional : rule_hit
  B ML          : rule_hit OR ml_malicious
  C LLM         : rule_hit            (LLM changes investigation, NOT detection)
  D combined    : (rule_hit OR ml_malicious OR anomaly) AND risk_score >= ALERT_RISK_THRESHOLD
"""
from __future__ import annotations

import hashlib
import json
import logging

import numpy as np
import pandas as pd

import config
from detection.rule_engine import evaluate_endpoint, evaluate_flows
from mitre import attack_mapping
from risk_engine import severity as sev
from risk_engine.risk_calculator import RiskInputs, calculate

log = logging.getLogger(__name__)
INFERENCE_LATENCY_S = 0.5      # modelled batch-inference delay added to ML detection time (assumption)
ENDPOINT_CONF_PROXY = 60.0     # endpoint alerts have no ML model: neutral rule-confidence proxy for the ML-confidence input


def _external(ip) -> bool:
    return not str(ip).startswith(("10.", "192.168.", "172.16."))


def score_flows(flows: pd.DataFrame, predictor) -> pd.DataFrame:
    """Rules + ML + anomaly + risk for every flow. Returns the frame with decision columns for configs A-D."""
    df = evaluate_flows(flows)
    ml = predictor.predict_flows(df)
    df = pd.concat([df, ml], axis=1)
    df["det_time_rule"] = df["rule_detect_time"]
    df["det_time_ml"] = df["timestamp"] + pd.to_timedelta(df["duration"], unit="s") + pd.Timedelta(seconds=INFERENCE_LATENCY_S)
    cand = df["rule_hit"] | (df["ml_is_malicious"] == 1) | (df["is_anomaly"] == 1)
    df["category"] = np.where(df["ml_is_malicious"] == 1, df["ml_category"],
                      np.where(df["rule_hit"], df["rule_category"], np.where(df["is_anomaly"] == 1, "Anomaly", None)))
    df.loc[~cand, "category"] = None
    risk, level, comps, mitre, ti = [np.nan] * len(df), [None] * len(df), [None] * len(df), [None] * len(df), [None] * len(df)
    seen: dict[str, int] = {}
    for pos, r in enumerate(df.itertuples()):
        if not cand.iloc[pos]:
            continue
        cat = r.category
        m = attack_mapping.map_detection(cat, list(r.rule_ids))
        prior = seen.get(r.src_ip, 0); seen[r.src_ip] = prior + 1
        inp = RiskInputs(severity=sev.severity_for(cat, r.rule_severity), impact=sev.impact_for(cat),
                         ml_confidence=float(r.ml_prob_malicious) * 100, asset_criticality=sev.asset_criticality_for(r.hostname),
                         exploitability=sev.exploitability_for(cat, _external(r.src_ip)), ti_reputation=sev.ti_reputation(r.src_ip),
                         recurrence=min(prior, 20), mitre_tactic=m[0]["tactic"] if m else None)
        res = calculate(inp)
        risk[pos], level[pos], comps[pos], mitre[pos] = res["score"], res["level"], res, m
    df["risk_score"], df["risk_level"], df["risk_detail"], df["mitre"] = risk, level, comps, mitre
    df["alert_A"] = df["rule_hit"]
    df["alert_B"] = df["rule_hit"] | (df["ml_is_malicious"] == 1)
    df["alert_C"] = df["rule_hit"]
    df["alert_D"] = cand & (df["risk_score"] >= config.ALERT_RISK_THRESHOLD)
    df["det_time_A"] = df["det_time_rule"]
    df["det_time_B"] = df[["det_time_rule", "det_time_ml"]].where(df[["rule_hit", "ml_is_malicious"]].astype(bool).values).min(axis=1)
    df["det_time_D"] = df[["det_time_rule", "det_time_ml"]].where(
        np.column_stack([df["rule_hit"].values, (df["ml_is_malicious"].values == 1) | (df["is_anomaly"].values == 1)])).min(axis=1)
    df["det_time_C"] = df["det_time_A"]
    return df


def score_endpoint(ep: pd.DataFrame) -> pd.DataFrame:
    df = evaluate_endpoint(ep)
    if df.empty:
        return df
    risk, level, comps, mitre = [np.nan] * len(df), [None] * len(df), [None] * len(df), [None] * len(df)
    seen: dict = {}
    for pos, r in enumerate(df.itertuples()):
        if not r.rule_hit:
            continue
        cat = r.rule_category
        m = attack_mapping.map_detection(cat, list(r.rule_ids))
        key = r.hostname; prior = seen.get(key, 0); seen[key] = prior + 1
        inp = RiskInputs(severity=sev.severity_for(cat, r.rule_severity), impact=sev.impact_for(cat), ml_confidence=ENDPOINT_CONF_PROXY,
                         asset_criticality=sev.asset_criticality_for(r.hostname),
                         exploitability=sev.exploitability_for(cat, _external(r.src_ip) if isinstance(r.src_ip, str) else False),
                         ti_reputation=sev.ti_reputation(r.src_ip if isinstance(r.src_ip, str) else r.dst_ip if isinstance(r.dst_ip, str) else None),
                         recurrence=min(prior, 20), mitre_tactic=m[0]["tactic"] if m else None)
        res = calculate(inp)
        risk[pos], level[pos], comps[pos], mitre[pos] = res["score"], res["level"], res, m
    df["category"] = df["rule_category"]
    df["risk_score"], df["risk_level"], df["risk_detail"], df["mitre"] = risk, level, comps, mitre
    df["det_time_D"] = df["rule_detect_time"]
    return df


def group_incidents(df: pd.DataFrame, mask: pd.Series, key_cols: list[str], det_col: str, bucket: str = "10min") -> pd.DataFrame:
    """Aggregate alerting events into analyst-facing incidents (same key + category within a time bucket)."""
    a = df[mask].copy()
    if a.empty:
        return a
    a["bucket"] = a["timestamp"].dt.floor(bucket)
    a["_cat"] = a["category"].fillna("Unknown")
    g = a.groupby(key_cols + ["_cat", "bucket"], sort=False)
    rep_idx = g["risk_score"].idxmax() if a["risk_score"].notna().any() else g["timestamp"].idxmin()
    rep = a.loc[rep_idx.values].copy()
    rep["event_count"] = g["timestamp"].transform("size").loc[rep_idx.values].values
    rep["first_event_time"] = g["timestamp"].transform("min").loc[rep_idx.values].values
    rep["group_detect_time"] = g[det_col].transform("min").loc[rep_idx.values].values
    rep["group_gt"] = g["gt_label"].transform("max").loc[rep_idx.values].values
    return rep.sort_values("group_detect_time").reset_index(drop=True)


def detection_method(r) -> str:
    parts = []
    if r.get("rule_hit"):
        parts.append("rule")
    if r.get("ml_is_malicious") == 1:
        parts.append("ml")
    if r.get("is_anomaly") == 1:
        parts.append("anomaly")
    return "+".join(parts) or "none"


def to_alert_rows(groups: pd.DataFrame, workload: str, with_ml: bool) -> list[dict]:
    from evaluation.soc_metrics import simulate_queue
    if groups.empty:
        return []
    sim = simulate_queue(groups["group_detect_time"], groups["risk_score"], time_factor=config.SOC_SIM["llm_time_factor"])
    end = groups["group_detect_time"].max() + pd.Timedelta(hours=1)
    rows = []
    for i, r in enumerate(groups.to_dict("records")):
        ack, resp = sim["acknowledged_at"].iloc[i], sim["responded_at"].iloc[i]
        status = "Contained" if resp <= end and i % 3 == 0 else "Investigating" if ack <= end - pd.Timedelta(hours=1) and i % 2 == 0 else "New"
        if status == "New":
            ack = resp = None
        elif status == "Investigating":
            resp = None
        dm = detection_method(r)
        rd = r["risk_detail"] or {}
        rows.append({
            "alert_id": "ALT-" + hashlib.sha1(str(r["event_id"]).encode()).hexdigest()[:8].upper(), "event_id": r["event_id"],
            "title": f"{r['category']} - {r.get('src_ip') if isinstance(r.get('src_ip'), str) else r.get('hostname')}" + (f" -> {r['dst_ip']}" if isinstance(r.get("dst_ip"), str) else ""),
            "source": r["source"], "created_at": r["first_event_time"], "detected_at": r["group_detect_time"], "acknowledged_at": ack,
            "responded_at": resp, "timestamp_source": "simulated" if ack is not None else "none",
            "detection_method": dm, "rule_ids": ",".join(r["rule_ids"]), "rule_names": r["rule_names"],
            "ml_model": r.get("ml_model") if with_ml else "n/a (endpoint events: rule-detected)",
            "ml_prediction": r.get("ml_category") if with_ml else r["category"], "ml_confidence": r.get("ml_prob_malicious") if with_ml else None,
            "anomaly_score": r.get("anomaly_score") if with_ml else None, "is_anomaly": int(r.get("is_anomaly", 0) or 0) if with_ml else 0,
            "severity": rd.get("components", {}).get("severity", {}).get("value"), "impact": rd.get("components", {}).get("impact", {}).get("value"),
            "asset_criticality": rd.get("components", {}).get("asset_criticality", {}).get("value"),
            "exploitability": rd.get("components", {}).get("exploitability", {}).get("value"),
            "risk_score": r["risk_score"], "risk_level": r["risk_level"], "risk_components_json": json.dumps(rd, default=str),
            "attack_category": r["category"], "src_ip": r.get("src_ip") if isinstance(r.get("src_ip"), str) else None,
            "dst_ip": r.get("dst_ip") if isinstance(r.get("dst_ip"), str) else None, "hostname": r.get("hostname"),
            "username": r.get("username") if isinstance(r.get("username"), str) else None, "mitre_json": json.dumps(r["mitre"] or []),
            "status": status, "gt_label": r["group_gt"], "workload": workload, "event_count": r["event_count"]})
    return rows

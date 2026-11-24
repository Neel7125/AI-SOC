"""End-to-end pipeline: ingest -> normalise -> detect -> ML -> anomaly -> risk -> incidents -> DB."""
from __future__ import annotations

import json
import logging

import pandas as pd

import config
from database import repository as repo
from detection.alert_processor import group_incidents, score_endpoint, score_flows, to_alert_rows
from ingestion.csv_loader import load_flow_events
from ingestion.linux_parser import parse_auth_log
from ingestion.normalizer import to_event_rows
from ingestion.sysmon_parser import parse_sysmon
from ml_engine.predict import Predictor

log = logging.getLogger(__name__)
OFFSET_FILE = config.PROCESSED_DIR / "stream_offset.json"


def split_live(live: pd.DataFrame, stream_fraction: float = 0.3) -> tuple[pd.DataFrame, pd.DataFrame]:
    cut = int(len(live) * (1 - stream_fraction))
    return live.iloc[:cut].reset_index(drop=True), live.iloc[cut:].reset_index(drop=True)


def process_flow_batch(flows: pd.DataFrame, predictor: Predictor, workload: str) -> dict:
    scored = score_flows(flows, predictor)
    repo.insert_events(to_event_rows(scored))
    groups = group_incidents(scored, scored["alert_D"], ["src_ip"], "det_time_D")
    rows = to_alert_rows(groups, workload, with_ml=True)
    repo.insert_alerts(rows)
    return {"flows": len(flows), "flow_alerts_events": int(scored["alert_D"].sum()), "incidents": len(rows)}


def process_endpoint_batch(ep: pd.DataFrame, workload: str) -> dict:
    scored = score_endpoint(ep)
    repo.insert_events(to_event_rows(scored))
    hit = scored["rule_hit"]
    groups = group_incidents(scored, hit, ["hostname"], "det_time_D")
    rows = to_alert_rows(groups, workload, with_ml=False)
    repo.insert_alerts(rows)
    return {"endpoint_events": len(ep), "incidents": len(rows)}


def run_pipeline(stream_fraction: float = 0.3, reset: bool = True) -> dict:
    if reset:
        repo.reset_db()
        OFFSET_FILE.write_text(json.dumps({"offset": 0}))
    pred = Predictor()
    live = load_flow_events(config.SYNTH_DIR / "live_flows.csv")
    initial, _ = split_live(live, stream_fraction)
    out = {"flows": process_flow_batch(initial, pred, "live")}
    ep = pd.concat([parse_sysmon(config.SYNTH_DIR / "sysmon_events.jsonl"),
                    parse_auth_log(config.SYNTH_DIR / "auth.log", config.SYNTH_DIR / "auth_log_truth.csv")], ignore_index=True)
    out["endpoint"] = process_endpoint_batch(ep, "live")
    return out


def stream_batch(n: int = 300) -> dict:
    """Near-real-time replay of the held-back part of the live workload (SYNTHETIC)."""
    live = load_flow_events(config.SYNTH_DIR / "live_flows.csv")
    _, stream = split_live(live)
    off = json.loads(OFFSET_FILE.read_text())["offset"] if OFFSET_FILE.exists() else 0
    chunk = stream.iloc[off: off + n]
    if chunk.empty:
        return {"status": "stream exhausted", "offset": off}
    res = process_flow_batch(chunk.reset_index(drop=True), Predictor(), "stream")
    OFFSET_FILE.write_text(json.dumps({"offset": off + len(chunk)}))
    return {"status": "ok", "offset": off + len(chunk), "remaining": len(stream) - off - len(chunk), **res}

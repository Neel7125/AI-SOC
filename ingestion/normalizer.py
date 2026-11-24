"""Normalisation of heterogeneous log sources into a common event schema."""
from __future__ import annotations

import hashlib
import logging

import numpy as np
import pandas as pd

from ingestion.synthetic import FLOW_FEATURES

log = logging.getLogger(__name__)

COMMON_COLS = ["event_id", "timestamp", "source", "event_type", "src_ip", "dst_ip", "dst_port", "protocol",
               "hostname", "username", "process", "parent_process", "command_line", "file_path", "description",
               "gt_label", "gt_category"]


def make_id(prefix: str, *parts) -> str:
    return f"{prefix}-" + hashlib.sha1("|".join(map(str, parts)).encode()).hexdigest()[:12]


def deduplicate(df: pd.DataFrame, subset: list[str] | None = None) -> pd.DataFrame:
    before = len(df)
    df = df.drop_duplicates(subset=subset).reset_index(drop=True)
    if before != len(df):
        log.info("Removed %d duplicate records", before - len(df))
    return df


def complete_flow_features(df: pd.DataFrame) -> pd.DataFrame:
    """Derive flow features from raw counters when only some are available (e.g. Zeek conn.log)."""
    df = df.copy()
    for c in FLOW_FEATURES:
        if c not in df:
            df[c] = np.nan
    tot_p = (df["fwd_pkts"].fillna(0) + df["bwd_pkts"].fillna(0)).clip(lower=1)
    tot_b = df["fwd_bytes"].fillna(0) + df["bwd_bytes"].fillna(0)
    dur = df["duration"].clip(lower=1e-3)
    df["bytes_per_s"] = df["bytes_per_s"].fillna(tot_b / dur)
    df["pkts_per_s"] = df["pkts_per_s"].fillna(tot_p / dur)
    df["avg_pkt_size"] = df["avg_pkt_size"].fillna(tot_b / tot_p)
    df["iat_mean"] = df["iat_mean"].fillna(dur / tot_p)
    df["fwd_pkt_len_mean"] = df["fwd_pkt_len_mean"].fillna(df["fwd_bytes"] / df["fwd_pkts"].clip(lower=1))
    df["bwd_pkt_len_mean"] = df["bwd_pkt_len_mean"].fillna(df["bwd_bytes"] / df["bwd_pkts"].clip(lower=1))
    df["protocol_num"] = df["protocol_num"].fillna(6)
    return df


def normalize_flows(df: pd.DataFrame, source: str = "flow") -> pd.DataFrame:
    df = df.copy()
    if "flow_id" not in df:
        df["flow_id"] = [make_id("FLW", r.timestamp, r.src_ip, r.dst_ip, r.dst_port, i) for i, r in enumerate(df.itertuples())]
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp", "src_ip", "dst_ip"])        # events without these cannot be correlated
    df = deduplicate(df, subset=["flow_id"])
    df = complete_flow_features(df)
    for c in ("hostname", "username"):
        if c not in df:
            df[c] = np.nan
    df["hostname"] = df["hostname"].fillna("unknown")
    df["event_id"] = df["flow_id"]
    df["source"] = source
    df["event_type"] = "network_flow"
    df["protocol"] = np.where(df["protocol_num"] == 17, "udp", "tcp")
    df["process"] = np.nan; df["parent_process"] = np.nan; df["command_line"] = np.nan; df["file_path"] = np.nan
    df["description"] = [f"Flow {r.src_ip} -> {r.dst_ip}:{int(r.dst_port)} {int(r.fwd_pkts)}/{int(r.bwd_pkts)} pkts, {int(r.fwd_bytes)}B out, {r.duration:.2f}s"
                         for r in df.itertuples()]
    if "is_malicious" in df:
        df["gt_label"] = df["is_malicious"].astype(int)
        df["gt_category"] = df.get("attack_category", "BENIGN")
    else:
        df["gt_label"] = np.nan; df["gt_category"] = np.nan
    return df.sort_values("timestamp").reset_index(drop=True)


def normalize_endpoint(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])
    for c in COMMON_COLS:
        if c not in df:
            df[c] = np.nan
    df["hostname"] = df["hostname"].fillna("unknown")
    df["username"] = df["username"].fillna("unknown")
    df = deduplicate(df, subset=[c for c in COMMON_COLS if c != "event_id"])
    return df.sort_values("timestamp").reset_index(drop=True)[COMMON_COLS]


def to_event_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Prepare a normalised frame for DB insertion (flow features packed as JSON)."""
    import json
    out = df.copy()
    if "fwd_pkts" in out:
        out["features_json"] = [json.dumps({k: (None if pd.isna(r[k]) else float(r[k])) for k in FLOW_FEATURES}) for r in out[FLOW_FEATURES].to_dict("records")]
    else:
        out["features_json"] = None
    if "parent_process" in out:
        mask = out["parent_process"].notna() & out["command_line"].notna()
        out.loc[mask, "description"] = out.loc[mask, "description"].astype(str) + " | parent=" + out.loc[mask, "parent_process"].astype(str)
    return out

"""CSV / JSON security-log ingestion (fallback when Splunk is unavailable)."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd

from ingestion.normalizer import normalize_flows


def load_table(path: str | Path) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {p}")
    if p.suffix.lower() == ".csv":
        return pd.read_csv(p)
    if p.suffix.lower() == ".jsonl":
        return pd.DataFrame([json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()])
    if p.suffix.lower() == ".json":
        data = json.loads(p.read_text(encoding="utf-8"))
        return pd.DataFrame(data if isinstance(data, list) else data.get("results", data))
    raise ValueError(f"Unsupported file type: {p.suffix}")


def load_flow_events(path: str | Path) -> pd.DataFrame:
    """Load flow records (must include timestamp, src_ip, dst_ip, dst_port and flow counters)."""
    df = load_table(path)
    required = {"timestamp", "src_ip", "dst_ip", "dst_port", "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Flow file missing required columns: {sorted(missing)}")
    return normalize_flows(df, source="csv")

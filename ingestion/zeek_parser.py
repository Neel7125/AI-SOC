"""Zeek conn.log (TSV) parser -> normalised network-flow records."""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from ingestion.normalizer import normalize_flows


def parse_zeek_conn(path: str | Path) -> pd.DataFrame:
    fields: list[str] = []
    rows = []
    for ln in Path(path).read_text(encoding="utf-8").splitlines():
        if ln.startswith("#fields"):
            fields = ln.split("\t")[1:]
        elif ln and not ln.startswith("#") and fields:
            parts = ln.split("\t")
            if len(parts) == len(fields):
                rows.append(dict(zip(fields, parts)))
    if not rows:
        return pd.DataFrame()
    z = pd.DataFrame(rows)
    num = lambda c: pd.to_numeric(z.get(c), errors="coerce")
    df = pd.DataFrame({
        "flow_id": z["uid"], "timestamp": pd.to_datetime(num("ts"), unit="s"), "src_ip": z["id.orig_h"], "dst_ip": z["id.resp_h"],
        "dst_port": num("id.resp_p"), "protocol_num": z["proto"].map({"tcp": 6, "udp": 17}).fillna(6),
        "duration": num("duration").fillna(0), "fwd_bytes": num("orig_bytes").fillna(0), "bwd_bytes": num("resp_bytes").fillna(0),
        "fwd_pkts": num("orig_pkts").fillna(0), "bwd_pkts": num("resp_pkts").fillna(0),
        "rst_count": z["conn_state"].isin(["RSTO", "RSTR", "REJ"]).astype(int)})
    return normalize_flows(df, source="zeek")

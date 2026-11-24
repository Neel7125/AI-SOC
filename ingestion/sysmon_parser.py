"""Sysmon (JSON-lines export) parser."""
from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd

from ingestion.normalizer import make_id, normalize_endpoint

log = logging.getLogger(__name__)
EVENT_TYPES = {1: "process_create", 3: "network_connect", 11: "file_create", 13: "registry_set", 22: "dns_query"}


def parse_sysmon_records(records: list[dict]) -> pd.DataFrame:
    rows = []
    for i, r in enumerate(records):
        try:
            eid = int(r.get("EventID", 0))
            et = EVENT_TYPES.get(eid, f"sysmon_{eid}")
            img = r.get("Image", ""); cmd = r.get("CommandLine") or ""; tgt = r.get("TargetFilename") or ""
            dip = r.get("DestinationIp") or np.nan; dport = r.get("DestinationPort") or np.nan
            desc = {"process_create": f"Process created: {cmd or img}", "file_create": f"File created: {tgt} by {img}",
                    "network_connect": f"Network connection by {img} to {dip}:{dport}"}.get(et, f"{et}: {img}")
            cat = r.get("_synthetic_category")
            rows.append({"event_id": make_id("SYS", r.get("UtcTime"), r.get("Computer"), cmd, tgt, dip, dport, i),
                         "timestamp": r.get("UtcTime"), "source": "sysmon", "event_type": et, "src_ip": np.nan, "dst_ip": dip,
                         "dst_port": dport, "protocol": "tcp" if et == "network_connect" else np.nan,
                         "hostname": r.get("Computer"), "username": r.get("User"), "process": img,
                         "parent_process": r.get("ParentImage"), "command_line": cmd or np.nan, "file_path": tgt or np.nan,
                         "description": desc, "gt_label": (0 if cat == "BENIGN" else 1) if cat else np.nan, "gt_category": cat})
        except (ValueError, TypeError) as exc:      # malformed record: skip but log
            log.warning("Skipping malformed sysmon record %d: %s", i, exc)
    return normalize_endpoint(pd.DataFrame(rows)) if rows else pd.DataFrame()


def parse_sysmon(path: str | Path) -> pd.DataFrame:
    recs = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError:
                log.warning("Bad JSON line skipped")
    return parse_sysmon_records(recs)

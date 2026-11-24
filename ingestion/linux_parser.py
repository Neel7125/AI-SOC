"""Linux auth.log (OpenSSH) parser."""
from __future__ import annotations

import logging
import re
from pathlib import Path

import numpy as np
import pandas as pd

from ingestion.normalizer import make_id, normalize_endpoint

log = logging.getLogger(__name__)
LINE = re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d+)\s+(?P<time>[\d:]{8})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+"
                  r"(?P<res>Failed|Accepted) password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+")


def parse_auth_lines(lines: list[str], year: int = 2026, truth: list[str] | None = None) -> pd.DataFrame:
    rows = []
    for i, ln in enumerate(lines):
        m = LINE.match(ln)
        if not m:
            continue
        ts = pd.to_datetime(f"{year} {m['mon']} {m['day']} {m['time']}", format="%Y %b %d %H:%M:%S", errors="coerce")
        failed = m["res"] == "Failed"
        cat = truth[i] if truth else None
        rows.append({"event_id": make_id("AUTH", ln, i), "timestamp": ts, "source": "linux_auth",
                     "event_type": "ssh_login_failed" if failed else "ssh_login_success", "src_ip": m["ip"], "dst_ip": np.nan,
                     "dst_port": 22, "protocol": "tcp", "hostname": m["host"], "username": m["user"], "process": "sshd",
                     "command_line": np.nan, "file_path": np.nan, "parent_process": np.nan,
                     "description": f"SSH {'failed' if failed else 'successful'} password login for {m['user']} from {m['ip']}",
                     "gt_label": (0 if cat == "BENIGN" else 1) if cat else np.nan, "gt_category": cat})
    return normalize_endpoint(pd.DataFrame(rows)) if rows else pd.DataFrame()


def parse_auth_log(path: str | Path, truth_path: str | Path | None = None) -> pd.DataFrame:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    truth = None
    if truth_path and Path(truth_path).exists():
        truth = pd.read_csv(truth_path)["category"].tolist()
    return parse_auth_lines(lines, truth=truth)

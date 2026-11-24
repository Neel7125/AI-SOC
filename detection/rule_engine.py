"""Rule/signature-based detection engine (Sigma-style rules implemented as vectorised pandas predicates)."""
from __future__ import annotations

import re
import warnings
from dataclasses import dataclass
from typing import Callable

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore", message="This pattern is interpreted as a regular expression")

from detection.correlation import add_auth_windows, add_flow_windows


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    severity: int          # 0-100
    category: str
    description: str
    predicate: Callable[[pd.DataFrame], pd.Series]
    window_based: bool = False


def _is_external(s: pd.Series) -> pd.Series:
    return ~s.astype(str).str.startswith(("10.", "192.168.", "172.16."))


def _rx(series: pd.Series, pattern: str) -> pd.Series:
    return series.fillna("").astype(str).str.contains(pattern, flags=re.IGNORECASE, regex=True)


FLOW_RULES = [
    Rule("NET-001", "Port scan (>=20 distinct ports/min from one source)", 55, "PortScan",
         "Many tiny SYN flows to many ports from one source in 60 s.",
         lambda d: (d["win_unique_ports"] >= 20) & (d["fwd_pkts"] <= 3), True),
    Rule("NET-002", "SYN/packet flood (>=1500 pkts/s and >=100 pkts)", 80, "DoS",
         "Extreme packet rate towards a service.", lambda d: (d["pkts_per_s"] >= 1500) & (d["fwd_pkts"] >= 100)),
    Rule("NET-003", "Brute force (>=10 auth-port flows/min from one source)", 70, "BruteForce",
         "Repeated connections to SSH/RDP/FTP from the same source.", lambda d: d["win_auth_flows"] >= 10, True),
    Rule("NET-004", "Large outbound transfer (>=2 MB to external host)", 75, "Exfiltration",
         "Large data volume leaving the network.", lambda d: _is_external(d["dst_ip"]) & (d["fwd_bytes"] >= 2_000_000)),
]
ENDPOINT_RULES = [
    Rule("EP-001", "Suspicious PowerShell execution", 75, "PowerShell Abuse",
         "Encoded commands, download cradles or hidden-window PowerShell.",
         lambda d: _rx(d["process"], r"powershell\.exe$") & _rx(d["command_line"],
                   r"-enc\b|-encodedcommand|downloadstring|\biex\b|invoke-expression|frombase64string|-w(indowstyle)?\s+hidden")),
    Rule("EP-002", "Privilege escalation indicators", 85, "Privilege Escalation",
         "Admin-group modification, privilege enumeration, credential dumping strings.",
         lambda d: _rx(d["command_line"], r"net\s+localgroup\s+administrators.*\/add|whoami\s+\/priv|sekurlsa|mimikatz|sc\s+config.*binpath")),
    Rule("EP-003", "Suspicious file activity", 70, "Suspicious File Activity",
         "Executables in Temp, shadow-copy deletion, ransomware-style extensions.",
         lambda d: (_rx(d["file_path"], r"\\temp\\.*\.(exe|ps1|bat|vbs|dll)$|\.locked$|README_DECRYPT")
                    | _rx(d["command_line"], r"vssadmin\s+delete\s+shadows"))),
    Rule("EP-004", "SSH brute force (>=5 failed logins / 5 min)", 70, "BruteForce",
         "Many failed SSH passwords from a single source.",
         lambda d: (d["event_type"] == "ssh_login_failed") & (d.get("win_failed_logins", 0) >= 5), True),
    Rule("EP-005", "Outbound connection to suspicious port", 65, "C2 Connection",
         "Connections to ports commonly used by reverse shells.",
         lambda d: (d["event_type"] == "network_connect") & d["dst_port"].isin([4444, 1337, 6667, 31337])),
]
ALL_RULES = {r.rule_id: r for r in FLOW_RULES + ENDPOINT_RULES}


def _apply(df: pd.DataFrame, rules: list[Rule]) -> pd.DataFrame:
    df = df.copy()
    hits = {r.rule_id: r.predicate(df).fillna(False).astype(bool) for r in rules}
    hm = pd.DataFrame(hits, index=df.index)
    df["rule_hit"] = hm.any(axis=1)
    df["rule_ids"] = hm.apply(lambda row: [c for c in hm.columns if row[c]], axis=1)
    df["rule_severity"] = [max([ALL_RULES[i].severity for i in ids], default=0) for ids in df["rule_ids"]]
    df["rule_category"] = [ALL_RULES[max(ids, key=lambda i: ALL_RULES[i].severity)].category if ids else None for ids in df["rule_ids"]]
    df["rule_names"] = [", ".join(ALL_RULES[i].name for i in ids) for ids in df["rule_ids"]]
    wb = {r.rule_id for r in rules if r.window_based}
    # Detection time: window rules fire at window close, per-event rules fire when the event is seen.
    end = df["win_end"] if "win_end" in df else df["timestamp"]
    df["rule_detect_time"] = [end.iloc[i] if any(r in wb for r in ids) else df["timestamp"].iloc[i] + pd.Timedelta(seconds=1)
                              for i, ids in enumerate(df["rule_ids"])]
    return df


def evaluate_flows(df: pd.DataFrame) -> pd.DataFrame:
    return _apply(add_flow_windows(df), FLOW_RULES)


def evaluate_endpoint(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    return _apply(add_auth_windows(df), ENDPOINT_RULES)

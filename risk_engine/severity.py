"""Severity / impact / exploitability / asset-criticality lookups and threat-intel context (all configurable tables)."""
from __future__ import annotations

import csv
from functools import lru_cache

import config

CATEGORY_IMPACT = {"DoS": 80, "Exfiltration": 90, "BruteForce": 60, "PortScan": 35, "PowerShell Abuse": 75,
                   "Privilege Escalation": 85, "Suspicious File Activity": 85, "C2 Connection": 80, "Anomaly": 40}
CATEGORY_SEVERITY = {"DoS": 75, "Exfiltration": 80, "BruteForce": 65, "PortScan": 50, "PowerShell Abuse": 75,
                     "Privilege Escalation": 85, "Suspicious File Activity": 75, "C2 Connection": 70, "Anomaly": 35}
CATEGORY_EXPLOIT = {"DoS": 60, "Exfiltration": 50, "BruteForce": 70, "PortScan": 40, "PowerShell Abuse": 75,
                    "Privilege Escalation": 70, "Suspicious File Activity": 60, "C2 Connection": 65, "Anomaly": 30}
ASSET_CRITICALITY = {"dc-01": 100, "srv-dc-01": 100, "db-01": 90, "srv-app-01": 80, "web-01": 70, "bastion-01": 70,
                     "ws-dev-03": 50, "ws-fin-01": 55, "ws-hr-02": 50}
DEFAULT_ASSET = 30


def severity_for(category: str | None, rule_severity: float = 0) -> float:
    return float(max(rule_severity or 0, CATEGORY_SEVERITY.get(category or "", 30)))


def impact_for(category: str | None) -> float:
    return float(CATEGORY_IMPACT.get(category or "", 40))


def exploitability_for(category: str | None, external_source: bool) -> float:
    return float(min(100, CATEGORY_EXPLOIT.get(category or "", 30) + (10 if external_source else 0)))


def asset_criticality_for(hostname: str | None) -> float:
    return float(ASSET_CRITICALITY.get((hostname or "").lower(), DEFAULT_ASSET))


@lru_cache(maxsize=1)
def _ti() -> list[tuple[str, float]]:
    p = config.SAMPLES_DIR / "threat_intel.csv"
    if not p.exists():
        return []
    with open(p, newline="", encoding="utf-8") as f:
        rows = [(r["prefix"], float(r["reputation"])) for r in csv.DictReader(f)]
    return sorted(rows, key=lambda x: -len(x[0]))


def ti_reputation(ip: str | None) -> float | None:
    """Longest-prefix match against the (synthetic demo) threat-intel list; None when unknown."""
    for prefix, rep in _ti():
        if ip and str(ip).startswith(prefix):
            return rep
    return None

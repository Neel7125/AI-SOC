"""Deterministic mapping of detections to ATT&CK techniques, with validation of any suggested IDs."""
from __future__ import annotations

from mitre.knowledge_base import lookup

CATEGORY_MAP = {
    "PortScan": ["T1046", "T1595.001"], "DoS": ["T1498"], "BruteForce": ["T1110.001", "T1021.004"],
    "Exfiltration": ["T1048", "T1567"], "PowerShell Abuse": ["T1059.001", "T1027"],
    "Privilege Escalation": ["T1548", "T1098", "T1003"], "Suspicious File Activity": ["T1486", "T1490", "T1074"],
    "C2 Connection": ["T1571", "T1071"],
}
RULE_MAP = {
    "NET-001": ["T1046"], "NET-002": ["T1498"], "NET-003": ["T1110.001"], "NET-004": ["T1048"],
    "EP-001": ["T1059.001"], "EP-002": ["T1098", "T1033"], "EP-003": ["T1486"], "EP-004": ["T1110.001"], "EP-005": ["T1571"],
}


def map_detection(category: str | None, rule_ids: list[str] | None = None) -> list[dict]:
    """Evidence-based mapping: derived from detection rule IDs and the classified category, never from LLM guesses."""
    ids: list[str] = []
    for r in rule_ids or []:
        ids += RULE_MAP.get(r, [])
    if not ids and category:
        ids += CATEGORY_MAP.get(category, [])
    seen, out = set(), []
    for t in ids:
        if t in seen:
            continue
        seen.add(t)
        k = lookup(t)
        if k:
            out.append({"id": t, "name": k["name"], "tactic": k["tactic"], "status": "detection-derived"})
    return out


def validate_suggestions(ids: list[str]) -> list[dict]:
    """LLM suggestions are accepted only if present in the knowledge base, and always labelled 'suggested'."""
    out = []
    for t in ids:
        k = lookup(t)
        out.append({"id": t, "name": k["name"] if k else "UNKNOWN", "tactic": k["tactic"] if k else "-",
                    "status": "suggested" if k else "rejected-not-in-knowledge-base"})
    return out

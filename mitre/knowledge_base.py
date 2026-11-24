"""MITRE ATT&CK knowledge base (curated subset; optional full STIX import)."""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

import config

log = logging.getLogger(__name__)
TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion",
                "Credential Access", "Discovery", "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact"]


def load_stix(path: str | Path) -> list[dict]:
    """Import techniques from an enterprise-attack STIX bundle (download from github.com/mitre/cti)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for o in data.get("objects", []):
        if o.get("type") != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tactics = [p["phase_name"].replace("-", " ").title() for p in o.get("kill_chain_phases", [])]
        out.append({"id": ext["external_id"], "name": o["name"], "tactic": tactics[0] if tactics else "Unknown",
                    "description": o.get("description", "")[:800]})
    return out


@lru_cache(maxsize=1)
def get_kb() -> dict[str, dict]:
    stix = config.RAW_DIR / "enterprise-attack.json"
    if stix.exists():
        try:
            return {t["id"]: t for t in load_stix(stix)}
        except Exception as exc:  # noqa: BLE001
            log.warning("STIX import failed (%s); using bundled subset", exc)
    items = json.loads((config.KNOWLEDGE_DIR / "mitre_attack_subset.json").read_text(encoding="utf-8"))
    return {t["id"]: t for t in items}


def lookup(tid: str) -> dict | None:
    return get_kb().get(tid)


def is_valid(tid: str) -> bool:
    return tid in get_kb()


def tactics() -> list[str]:
    present = {t["tactic"] for t in get_kb().values()}
    return [t for t in TACTIC_ORDER if t in present]

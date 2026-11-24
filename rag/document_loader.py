"""Load knowledge sources (ATT&CK, playbooks, IR procedures, Sigma docs, vulnerability notes)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import config
from mitre.knowledge_base import get_kb


@dataclass
class Doc:
    doc_id: str
    source: str
    title: str
    text: str


def load_markdown(path: Path) -> list[Doc]:
    text = path.read_text(encoding="utf-8")
    docs = []
    parts = re.split(r"^## ", text, flags=re.MULTILINE)
    for i, sec in enumerate(parts[1:] if len(parts) > 1 else parts):
        title, _, body = sec.partition("\n")
        docs.append(Doc(f"{path.stem}:{i}", path.name, title.strip(), body.strip()))
    return docs


def load_mitre() -> list[Doc]:
    return [Doc(f"mitre:{t['id']}", "MITRE ATT&CK", f"{t['id']} {t['name']} ({t['tactic']})", t["description"]) for t in get_kb().values()]


def load_all() -> list[Doc]:
    docs = load_mitre()
    for p in sorted(config.KNOWLEDGE_DIR.glob("*.md")):
        docs += load_markdown(p)
    # Optional user documents: drop .md files into data/knowledge/
    return docs

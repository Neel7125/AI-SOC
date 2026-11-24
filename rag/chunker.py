"""Word-window chunking with overlap; title is kept in every chunk for retrieval context."""
from __future__ import annotations

from dataclasses import dataclass

from rag.document_loader import Doc


@dataclass
class Chunk:
    chunk_id: str
    doc_id: str
    source: str
    title: str
    text: str


def chunk_docs(docs: list[Doc], max_words: int = 120, overlap: int = 20) -> list[Chunk]:
    if overlap >= max_words:
        raise ValueError("overlap must be smaller than max_words")
    out: list[Chunk] = []
    for d in docs:
        words = d.text.split()
        if len(words) <= max_words:
            spans = [(0, len(words))]
        else:
            spans, s = [], 0
            while s < len(words):
                spans.append((s, min(s + max_words, len(words))))
                if s + max_words >= len(words):
                    break
                s += max_words - overlap
        for n, (a, b) in enumerate(spans):
            out.append(Chunk(f"{d.doc_id}#{n}", d.doc_id, d.source, d.title, " ".join(words[a:b])))
    return out

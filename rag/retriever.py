"""Top-K retrieval with similarity scores, source attribution, context filtering and retrieval logging."""
from __future__ import annotations

import logging

import config
from rag.chunker import chunk_docs
from rag.document_loader import load_all
from rag.vector_store import INDEX_PATH, VectorStore

log = logging.getLogger(__name__)
_STORE: VectorStore | None = None


def build_index() -> VectorStore:
    vs = VectorStore().build(chunk_docs(load_all()))
    vs.save()
    log.info("RAG index built: %d chunks (backend=%s)", len(vs.chunks), vs.embedder.backend)
    return vs


def get_store() -> VectorStore:
    global _STORE
    if _STORE is None:
        _STORE = VectorStore.load() if INDEX_PATH.exists() else build_index()
    return _STORE


def retrieve(query: str, k: int | None = None, min_score: float | None = None, log_to_db: bool = True) -> list[dict]:
    from llm_engine.prompts import looks_like_injection
    k = k or config.RAG_TOP_K
    min_score = config.RAG_MIN_SCORE if min_score is None else min_score
    res = []
    for ch, sc in get_store().search(query, k):
        if sc < min_score:                      # context filtering: drop weak matches
            continue
        res.append({"chunk_id": ch.chunk_id, "source": ch.source, "title": ch.title, "score": round(sc, 4),
                    "text": ch.text, "flagged_injection": looks_like_injection(ch.text)})
    res = [r for r in res if not r["flagged_injection"]]          # retrieved text is untrusted: drop injected instructions
    if log_to_db:
        try:
            from database.repository import log_retrieval
            log_retrieval(query, k, [{k2: r[k2] for k2 in ("chunk_id", "source", "title", "score")} for r in res])
        except Exception as exc:  # noqa: BLE001
            log.debug("retrieval log skipped: %s", exc)
    return res

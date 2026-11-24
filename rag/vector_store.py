"""Cosine-similarity vector store (FAISS is used automatically for dense embeddings when installed)."""
from __future__ import annotations

import logging

import joblib
import numpy as np
import scipy.sparse as sp

import config
from rag.chunker import Chunk
from rag.embeddings import Embedder

log = logging.getLogger(__name__)
INDEX_PATH = config.MODELS_DIR / "rag_index.joblib"


class VectorStore:
    def __init__(self):
        self.chunks: list[Chunk] = []
        self.embedder = Embedder()
        self.matrix = None
        self._faiss = None

    def build(self, chunks: list[Chunk]) -> "VectorStore":
        self.chunks = chunks
        self.matrix = self.embedder.fit_transform([f"{c.title}. {c.text}" for c in chunks])
        self._maybe_faiss()
        return self

    def _maybe_faiss(self) -> None:
        self._faiss = None
        if isinstance(self.matrix, np.ndarray):
            try:
                import faiss
                idx = faiss.IndexFlatIP(self.matrix.shape[1]); idx.add(self.matrix.astype("float32")); self._faiss = idx
            except ImportError:
                pass

    def search(self, query: str, k: int = 4) -> list[tuple[Chunk, float]]:
        q = self.embedder.transform([query])
        if self._faiss is not None:
            sc, ix = self._faiss.search(np.asarray(q, dtype="float32"), k)
            return [(self.chunks[i], float(s)) for s, i in zip(sc[0], ix[0]) if i >= 0]
        sims = (self.matrix @ q.T)
        sims = sims.toarray().ravel() if sp.issparse(sims) else np.asarray(sims).ravel()   # rows are L2-normalised => cosine
        top = np.argsort(-sims)[:k]
        return [(self.chunks[i], float(sims[i])) for i in top]

    def save(self, path=INDEX_PATH) -> None:
        self._faiss = None
        joblib.dump(self, path)

    @staticmethod
    def load(path=INDEX_PATH) -> "VectorStore":
        vs = joblib.load(path)
        vs._maybe_faiss()
        return vs

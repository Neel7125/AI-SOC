"""Embedding backends: TF-IDF (default, fully offline) or Sentence-Transformers (EMBEDDING_BACKEND=sbert)."""
from __future__ import annotations

import logging

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

import config

log = logging.getLogger(__name__)


class Embedder:
    def __init__(self, backend: str | None = None):
        self.backend = backend or config.EMBEDDING_BACKEND
        self._tfidf: TfidfVectorizer | None = None
        self._sbert = None

    def fit_transform(self, texts: list[str]):
        if self.backend == "sbert":
            try:
                from sentence_transformers import SentenceTransformer
                self._sbert = SentenceTransformer(config.SBERT_MODEL)
                return np.asarray(self._sbert.encode(texts, normalize_embeddings=True))
            except Exception as exc:  # noqa: BLE001
                log.warning("sentence-transformers unavailable (%s); falling back to TF-IDF", exc)
                self.backend = "tfidf"
        self._tfidf = TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, stop_words="english", min_df=1)
        return self._tfidf.fit_transform(texts)

    def transform(self, texts: list[str]):
        if self.backend == "sbert" and self._sbert is not None:
            return np.asarray(self._sbert.encode(texts, normalize_embeddings=True))
        return self._tfidf.transform(texts)

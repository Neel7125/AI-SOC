"""Dataset-specific preprocessing: loading, validation, EDA, cleaning, encoding, selection, leakage-safe splitting."""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

import config

log = logging.getLogger(__name__)
SEED = 42


def load_dataset(name: str | None = None) -> tuple[pd.DataFrame, dict]:
    name = name or config.ACTIVE_DATASET
    if name not in config.DATASETS:
        raise KeyError(f"Unknown dataset '{name}'. Configured: {list(config.DATASETS)}")
    cfg = dict(config.DATASETS[name], name=name)
    p = Path(cfg["path"])
    if not p.exists():
        raise FileNotFoundError(f"Dataset '{name}' not found at {p}. Set its path in .env (see README) - datasets are never auto-downloaded.")
    df = pd.read_csv(p, low_memory=False)
    df.columns = [c.strip() for c in df.columns]
    validate(df, cfg)
    return df, cfg


def validate(df: pd.DataFrame, cfg: dict) -> None:
    if cfg["label_col"] not in df.columns:
        raise ValueError(f"Label column '{cfg['label_col']}' missing. Columns: {list(df.columns)[:15]}...")
    if len(df) < 100:
        raise ValueError("Dataset too small (<100 rows)")
    if df[cfg["label_col"]].nunique() < 2:
        raise ValueError("Dataset needs at least two classes")


def clean(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Replace inf, drop duplicates & rows without label. Duplicates are removed BEFORE splitting (prevents train/test leakage)."""
    df = df.replace([np.inf, -np.inf], np.nan)
    n0 = len(df)
    df = df.dropna(subset=[cfg["label_col"]]).drop_duplicates().reset_index(drop=True)
    log.info("clean(): %d -> %d rows", n0, len(df))
    df[cfg["label_col"]] = df[cfg["label_col"]].astype(str).str.strip()
    return df


def eda(df: pd.DataFrame, cfg: dict) -> dict:
    lab = cfg["label_col"]
    counts = df[lab].value_counts()
    num = df.select_dtypes("number")
    out = {"dataset": cfg["name"], "rows": int(len(df)), "columns": int(df.shape[1]),
           "class_counts": {k: int(v) for k, v in counts.items()},
           "imbalance_ratio_majority_to_minority": round(float(counts.max() / counts.min()), 2),
           "missing_values": {k: int(v) for k, v in df.isna().sum().items() if v > 0},
           "numeric_summary": json.loads(num.describe().T[["mean", "std", "min", "max"]].round(4).to_json(orient="index"))}
    (config.PROCESSED_DIR / f"eda_{cfg['name']}.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    return out


@dataclass
class Preprocessor:
    """Fitted on the TRAINING split only (medians, vocab, feature selection) -> no leakage."""
    drop_cols: list[str]
    label_col: str
    benign_label: str
    corr_threshold: float = 0.98
    feature_names: list[str] = field(default_factory=list)
    medians: dict = field(default_factory=dict)
    cat_vocab: dict = field(default_factory=dict)
    classes: list[str] = field(default_factory=list)
    dataset: str = ""
    input_cols: list[str] = field(default_factory=list)

    def _expand(self, X: pd.DataFrame) -> pd.DataFrame:
        X = X.drop(columns=[c for c in self.drop_cols + [self.label_col] if c in X.columns])
        if self.input_cols:
            X = X[[c for c in X.columns if c in self.input_cols]]
        parts = {}
        for c in X.columns:
            if c in self.cat_vocab:
                for v in self.cat_vocab[c]:
                    parts[f"{c}={v}"] = (X[c].astype(str) == v).astype(float)
            else:
                parts[c] = pd.to_numeric(X[c], errors="coerce")
        return pd.DataFrame(parts, index=X.index).replace([np.inf, -np.inf], np.nan)

    def fit(self, X: pd.DataFrame) -> "Preprocessor":
        Xd = X.drop(columns=[c for c in self.drop_cols + [self.label_col] if c in X.columns])
        self.input_cols = list(Xd.columns)
        self.cat_vocab = {c: Xd[c].value_counts().head(15).index.astype(str).tolist() for c in Xd.select_dtypes(exclude="number").columns}
        E = self._expand(X)
        E = E.loc[:, E.nunique(dropna=True) > 1]                              # drop constant columns
        corr = E.corr().abs()
        upper = corr.where(np.triu(np.ones(corr.shape, dtype=bool), k=1))
        drop = [c for c in upper.columns if (upper[c] > self.corr_threshold).any()]  # drop near-duplicate features
        E = E.drop(columns=drop)
        self.feature_names = list(E.columns)
        self.medians = E.median().to_dict()
        log.info("Feature selection kept %d features (dropped %d correlated)", len(self.feature_names), len(drop))
        return self

    def transform(self, X: pd.DataFrame) -> pd.DataFrame:
        E = self._expand(X)
        for c in self.feature_names:
            if c not in E:
                E[c] = np.nan
        E = E[self.feature_names]
        return E.fillna(pd.Series(self.medians)).astype(float)

    def save(self, path: Path | None = None) -> None:
        joblib.dump(self, path or config.MODELS_DIR / "preprocessor.joblib")

    @staticmethod
    def load(path: Path | None = None) -> "Preprocessor":
        p = path or config.MODELS_DIR / "preprocessor.joblib"
        if not p.exists():
            raise FileNotFoundError("Preprocessor not found - run `python scripts/train_all.py` first")
        return joblib.load(p)


@dataclass
class Splits:
    X_train: pd.DataFrame; X_val: pd.DataFrame; X_test: pd.DataFrame
    y_train: np.ndarray; y_val: np.ndarray; y_test: np.ndarray
    pre: Preprocessor; encoder: LabelEncoder; raw_test: pd.DataFrame

    @property
    def benign_idx(self) -> int:
        return int(self.encoder.transform([self.pre.benign_label])[0])


def prepare(name: str | None = None, save: bool = True) -> Splits:
    """Stratified 70/15/15 split -> fit preprocessing on train only."""
    df, cfg = load_dataset(name)
    df = clean(df, cfg)
    eda(df, cfg)
    enc = LabelEncoder().fit(df[cfg["label_col"]])
    y = enc.transform(df[cfg["label_col"]])
    idx = np.arange(len(df))
    tr, tmp = train_test_split(idx, test_size=.30, stratify=y, random_state=SEED)
    va, te = train_test_split(tmp, test_size=.50, stratify=y[tmp], random_state=SEED)
    pre = Preprocessor(cfg["drop_cols"], cfg["label_col"], cfg["benign_label"], classes=list(enc.classes_), dataset=cfg["name"])
    pre.fit(df.iloc[tr])
    if cfg["benign_label"] not in enc.classes_:
        raise ValueError(f"benign_label '{cfg['benign_label']}' not among classes {list(enc.classes_)}")
    if save:
        pre.save()
    f = lambda i: pre.transform(df.iloc[i])
    return Splits(f(tr), f(va), f(te), y[tr], y[va], y[te], pre, enc, df.iloc[te])


def apply_smote(X: pd.DataFrame, y: np.ndarray):
    """Optional oversampling - applied to the TRAINING split only."""
    try:
        from imblearn.over_sampling import SMOTE
    except ImportError as e:
        raise RuntimeError("imbalanced-learn is required for SMOTE") from e
    k = max(1, min(5, int(np.bincount(y).min()) - 1))
    Xr, yr = SMOTE(random_state=SEED, k_neighbors=k).fit_resample(X, y)
    return pd.DataFrame(Xr, columns=X.columns), yr

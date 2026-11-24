"""Model registry: metadata, training configuration and artifact locations."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import config
from ml_engine.base import BaseModel
from ml_engine.isolation_forest import IsolationForestModel

REG_PATH = config.MODELS_DIR / "registry.json"


def _read() -> dict:
    if REG_PATH.exists():
        return json.loads(REG_PATH.read_text(encoding="utf-8"))
    return {"models": {}, "best": None}


def register(name: str, meta: dict) -> None:
    reg = _read()
    reg["models"][name] = {**meta, "registered_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "artifact": f"{name}.joblib"}
    REG_PATH.write_text(json.dumps(reg, indent=2, default=str), encoding="utf-8")


def set_best(name: str) -> None:
    reg = _read(); reg["best"] = name
    REG_PATH.write_text(json.dumps(reg, indent=2), encoding="utf-8")


def get_registry() -> dict:
    return _read()


def best_name() -> str:
    b = _read().get("best")
    if not b:
        raise FileNotFoundError("No trained models. Run `python scripts/train_all.py`.")
    return b


def load_model(name: str | None = None) -> BaseModel:
    return BaseModel.load(config.MODELS_DIR / f"{name or best_name()}.joblib")


def load_anomaly() -> IsolationForestModel:
    return IsolationForestModel.load(config.MODELS_DIR / "isolation_forest.joblib")


def models_available() -> bool:
    return bool(_read().get("best")) and (config.MODELS_DIR / "isolation_forest.joblib").exists()

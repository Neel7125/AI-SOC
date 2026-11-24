"""Generate ML evaluation charts/metrics. Usage: python scripts/evaluate_all.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation.ml_evaluation import run_ml_evaluation  # noqa: E402

if __name__ == "__main__":
    r = run_ml_evaluation()
    print(json.dumps({k: v.get("binary") for k, v in r["metrics"].items()}, indent=2))

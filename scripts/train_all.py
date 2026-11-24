"""Train all ML models. Usage: python scripts/train_all.py [--dataset synthetic] [--smote]"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ml_engine.train import train_all  # noqa: E402

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--smote", action="store_true", help="oversample training split only")
    a = ap.parse_args()
    print(json.dumps(train_all(a.dataset, a.smote), indent=2))

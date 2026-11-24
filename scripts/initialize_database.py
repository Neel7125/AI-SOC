"""Run the full pipeline into the database. Usage: python scripts/initialize_database.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detection.pipeline import run_pipeline  # noqa: E402

if __name__ == "__main__":
    print(json.dumps(run_pipeline(), indent=2))

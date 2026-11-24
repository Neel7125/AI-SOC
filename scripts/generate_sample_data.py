"""Generate SYNTHETIC demo data (flows, Sysmon, auth.log, Zeek). Usage: python scripts/generate_sample_data.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ingestion.synthetic import generate_all  # noqa: E402

if __name__ == "__main__":
    print("Generated SYNTHETIC data:", generate_all())

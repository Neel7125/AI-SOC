"""Run the full detection pipeline on the current synthetic dataset.

Usage:
    python scripts/run_pipeline.py [--reset] [--stream N]

Options:
    --reset     Drop and re-create the database before running (default: True).
    --stream N  Also ingest N streamed flows after the initial batch (default: 0).

The pipeline steps:
  1. Load live_flows.csv (held-back initial batch)
  2. Predict with trained ML + isolation forest
  3. Evaluate rules (NET-001..004) + anomaly detection
  4. Calculate risk score per candidate event
  5. Group correlated events into analyst-facing incidents
  6. Persist events and alerts to SQLite
  7. Process endpoint events (Sysmon + auth.log)
  8. Optionally replay N streamed flows

Pre-conditions:
  - Synthetic data must exist: data/synthetic/*.csv, *.jsonl, *.log
    Run `python scripts/generate_sample_data.py` if missing.
  - Trained models must exist: models/*.joblib, models/registry.json
    Run `python scripts/train_all.py` if missing.

Outputs:
  - data/soc.db  (SQLite: events, alerts, risk_history, audit_log tables)
  - Console summary of events, flow incidents, and endpoint incidents.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the AI-SOC detection pipeline.")
    parser.add_argument("--no-reset", dest="reset", action="store_false", default=True,
                        help="Keep existing DB data (default: reset before run).")
    parser.add_argument("--stream", type=int, default=0, metavar="N",
                        help="Ingest N additional streamed flows after the initial batch.")
    args = parser.parse_args()

    # -- guard: synthetic data present? ---------------------------------------
    import config
    if not (config.SYNTH_DIR / "live_flows.csv").exists():
        print("Synthetic data not found. Run `python scripts/generate_sample_data.py` first.", file=sys.stderr)
        sys.exit(1)

    # -- guard: models present? -----------------------------------------------
    from ml_engine.model_registry import models_available
    if not models_available():
        print("No trained models found. Run `python scripts/train_all.py` first.", file=sys.stderr)
        sys.exit(1)

    # -- run pipeline ----------------------------------------------------------
    from detection.pipeline import run_pipeline, stream_batch
    from database import repository as repo

    log.info("Starting detection pipeline (reset=%s) ...", args.reset)
    result = run_pipeline(reset=args.reset)
    log.info("Pipeline finished: %s", result)

    # summary
    n_events = repo.count_events()
    n_alerts = len(repo.list_alerts())
    print(f"\n{'='*55}")
    print(f"  Pipeline complete")
    print(f"  Events in DB   : {n_events:,}")
    print(f"  Incidents (all): {n_alerts:,}")
    print(f"  Flow batch     : {result.get('flows', {})}")
    print(f"  Endpoint batch : {result.get('endpoint', {})}")

    # optional streaming
    if args.stream > 0:
        log.info("Streaming %d additional flows ...", args.stream)
        s_result = stream_batch(n=args.stream)
        log.info("Stream batch: %s", s_result)
        print(f"  Stream batch   : {s_result}")

    print(f"{'='*55}\n")
    print(f"Launch the dashboard:  streamlit run app.py")
    print(f"Launch the API:        uvicorn api.main:app --reload")


if __name__ == "__main__":
    main()

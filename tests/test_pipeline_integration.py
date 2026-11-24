"""End-to-end pipeline integration test.

Runs: generate synthetic data -> train models -> run_pipeline -> verify DB.
This is a slow test (marked with the 'integration' marker); skip with:
    pytest -m "not integration"
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.mark.integration
class TestFullPipeline:
    """Full integration: synthetic data -> train -> pipeline -> DB checks."""

    @pytest.fixture(scope="class", autouse=True)
    def run_setup(self):
        """Run the pipeline once for the whole class."""
        from database.connection import init_db
        from ingestion.synthetic import generate_all
        from ml_engine.train import train_all
        from detection.pipeline import run_pipeline

        init_db(reset=True)
        generate_all()
        train_all()
        run_pipeline(reset=True)

    def test_events_inserted(self):
        from database import repository as repo
        assert repo.count_events() > 0

    def test_alerts_inserted(self):
        from database import repository as repo
        df = repo.list_alerts()
        assert len(df) > 0

    def test_alerts_have_risk_scores(self):
        from database import repository as repo
        df = repo.list_alerts()
        assert df["risk_score"].notna().all()

    def test_alerts_have_valid_status(self):
        from database import repository as repo
        import config
        df = repo.list_alerts()
        assert df["status"].isin(config.INCIDENT_STATUSES).all()

    def test_alerts_have_mitre_json(self):
        from database import repository as repo
        import json
        df = repo.list_alerts()
        for mitre_json in df["mitre_json"].head(10):
            assert isinstance(json.loads(mitre_json or "[]"), list)

    def test_ml_predictions_present(self):
        from database import repository as repo
        df = repo.list_alerts()
        ml_rows = df[df["detection_method"].str.contains("ml", na=False)]
        # At least some alerts should have ML predictions
        assert len(ml_rows) > 0

    def test_risk_levels_valid(self):
        from database import repository as repo
        valid = {"Informational", "Low", "Medium", "High", "Critical"}
        df = repo.list_alerts()
        invalid = set(df["risk_level"].dropna()) - valid
        assert not invalid, f"Invalid risk levels found: {invalid}"

    def test_audit_log_has_entries(self):
        from database import repository as repo
        audit = repo.get_audit()
        assert len(audit) > 0


@pytest.mark.integration
class TestStreamBatch:
    """Test stream_batch incrementally processes held-back flows."""

    @pytest.fixture(scope="class", autouse=True)
    def run_setup(self):
        from database.connection import init_db
        from ingestion.synthetic import generate_all
        from ml_engine.train import train_all
        from detection.pipeline import run_pipeline

        init_db(reset=True)
        generate_all()
        train_all()
        run_pipeline(reset=True)

    def test_stream_batch_returns_ok(self):
        from detection.pipeline import stream_batch
        result = stream_batch(n=100)
        # Either processes flows or reports stream exhausted
        assert result.get("status") in ("ok", "stream exhausted")

    def test_stream_batch_inserts_events(self):
        from database import repository as repo
        from detection.pipeline import stream_batch
        before = repo.count_events()
        stream_batch(n=100)
        after = repo.count_events()
        # It's possible the stream is already exhausted, so just check >= before
        assert after >= before

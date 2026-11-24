"""Integration tests for database layer (uses a temporary SQLite DB)."""
import sys
import tempfile
from pathlib import Path

import pandas as pd
import pytest

# Insert project root so imports work without installation
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Redirect the DB to a tmp file before importing anything that uses it
import os, tempfile as _tf
_tmp_db = _tf.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["SOC_DB_PATH"] = _tmp_db.name

import config  # noqa: E402  config reads env, must come after os.environ set
config.DB_PATH = Path(_tmp_db.name)

from database.connection import init_db  # noqa: E402
from database import repository as repo   # noqa: E402


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db():
    """Reset DB before every test."""
    init_db(reset=True)
    yield
    # leave cleanup to OS tmp-file machinery


def _event(eid="evt-001", ts="2024-01-01T12:00:00", gt_label=0, gt_category="BENIGN") -> dict:
    return {"event_id": eid, "timestamp": ts, "source": "test", "event_type": "network_flow",
            "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dst_port": 80, "protocol": "TCP",
            "hostname": "ws-test-01", "username": "alice", "process": None, "command_line": None,
            "file_path": None, "description": "test event", "gt_label": gt_label,
            "gt_category": gt_category, "features_json": None}


def _alert(aid="ALT-00000001", eid="evt-001") -> dict:
    return {"alert_id": aid, "event_id": eid, "title": "Test Alert", "source": "test",
            "created_at": "2024-01-01T12:00:00", "detected_at": "2024-01-01T12:00:01",
            "acknowledged_at": None, "responded_at": None, "timestamp_source": "simulated",
            "detection_method": "rule", "rule_ids": "NET-002", "rule_names": "DoS",
            "ml_model": "random_forest", "ml_prediction": "DoS", "ml_confidence": 0.85,
            "anomaly_score": 70.0, "is_anomaly": 1,
            "severity": 70, "impact": 60, "asset_criticality": 50, "exploitability": 50,
            "risk_score": 65.0, "risk_level": "High", "risk_components_json": "{}",
            "attack_category": "DoS", "src_ip": "10.0.0.1", "dst_ip": "8.8.8.8",
            "hostname": "ws-test-01", "username": "alice",
            "mitre_json": "[]", "status": "New", "gt_label": 1, "workload": "live", "event_count": 3}


# ---------------------------------------------------------------------------
# events
# ---------------------------------------------------------------------------

class TestEvents:
    def test_insert_and_count(self):
        df = pd.DataFrame([_event("e1"), _event("e2")])
        inserted = repo.insert_events(df)
        assert inserted == 2
        assert repo.count_events() == 2

    def test_get_event(self):
        repo.insert_events(pd.DataFrame([_event("e-get")]))
        ev = repo.get_event("e-get")
        assert ev is not None
        assert ev["event_id"] == "e-get"

    def test_get_missing_event_returns_none(self):
        assert repo.get_event("does-not-exist") is None

    def test_insert_replace_on_duplicate(self):
        repo.insert_events(pd.DataFrame([_event("dup")]))
        repo.insert_events(pd.DataFrame([_event("dup", gt_label=1)]))
        assert repo.count_events() == 1  # replaced, not duplicated


# ---------------------------------------------------------------------------
# alerts
# ---------------------------------------------------------------------------

class TestAlerts:
    def test_insert_and_list(self):
        repo.insert_events(pd.DataFrame([_event()]))
        repo.insert_alerts([_alert()])
        df = repo.list_alerts()
        assert len(df) == 1
        assert df.iloc[0]["alert_id"] == "ALT-00000001"

    def test_get_alert(self):
        repo.insert_events(pd.DataFrame([_event()]))
        repo.insert_alerts([_alert()])
        a = repo.get_alert("ALT-00000001")
        assert a is not None
        assert a["title"] == "Test Alert"

    def test_get_missing_alert_returns_none(self):
        assert repo.get_alert("NONEXISTENT") is None

    def test_list_alerts_sorted_by_risk(self):
        repo.insert_events(pd.DataFrame([_event("e1"), _event("e2")]))
        a1 = _alert("ALT-A", "e1"); a1["risk_score"] = 90.0
        a2 = _alert("ALT-B", "e2"); a2["risk_score"] = 20.0
        repo.insert_alerts([a1, a2])
        df = repo.list_alerts()
        assert df.iloc[0]["alert_id"] == "ALT-A"


# ---------------------------------------------------------------------------
# status transitions
# ---------------------------------------------------------------------------

class TestStatusTransitions:
    def _setup_alert(self, aid="ALT-00000001", eid="evt-001"):
        repo.insert_events(pd.DataFrame([_event(eid)]))
        repo.insert_alerts([_alert(aid, eid)])

    def test_valid_new_to_investigating(self):
        self._setup_alert()
        repo.update_status("ALT-00000001", "Investigating", "analyst")
        a = repo.get_alert("ALT-00000001")
        assert a["status"] == "Investigating"

    def test_invalid_transition_raises(self):
        self._setup_alert()
        with pytest.raises(ValueError):
            repo.update_status("ALT-00000001", "Resolved", "analyst")  # New -> Resolved is not allowed

    def test_unknown_status_raises(self):
        self._setup_alert()
        with pytest.raises(ValueError):
            repo.update_status("ALT-00000001", "HACKEDSTATUS", "analyst")

    def test_acknowledged_at_set_on_investigating(self):
        self._setup_alert()
        repo.update_status("ALT-00000001", "Investigating", "analyst")
        a = repo.get_alert("ALT-00000001")
        assert a["acknowledged_at"] is not None

    def test_responded_at_set_on_resolved(self):
        self._setup_alert()
        repo.update_status("ALT-00000001", "Investigating", "analyst")
        repo.update_status("ALT-00000001", "Resolved", "analyst")
        a = repo.get_alert("ALT-00000001")
        assert a["responded_at"] is not None

    def test_closed_allows_no_further_transitions(self):
        self._setup_alert()
        repo.update_status("ALT-00000001", "Investigating")
        repo.update_status("ALT-00000001", "Resolved")
        repo.update_status("ALT-00000001", "Closed")
        with pytest.raises(ValueError):
            repo.update_status("ALT-00000001", "New")


# ---------------------------------------------------------------------------
# notes & evidence
# ---------------------------------------------------------------------------

class TestNotesAndEvidence:
    def _setup(self):
        repo.insert_events(pd.DataFrame([_event()]))
        repo.insert_alerts([_alert()])

    def test_add_note(self):
        self._setup()
        repo.add_note("ALT-00000001", "analyst1", "Investigating the alert.")
        notes = repo.get_notes("ALT-00000001")
        assert len(notes) == 1
        assert notes.iloc[0]["note"] == "Investigating the alert."

    def test_empty_note_raises(self):
        self._setup()
        with pytest.raises(ValueError):
            repo.add_note("ALT-00000001", "analyst1", "   ")

    def test_add_evidence(self):
        self._setup()
        repo.add_evidence("ALT-00000001", "analyst1", "Screenshot of connection log.")
        ev = repo.get_evidence("ALT-00000001")
        assert len(ev) == 1

    def test_empty_evidence_raises(self):
        self._setup()
        with pytest.raises(ValueError):
            repo.add_evidence("ALT-00000001", "analyst1", "")


# ---------------------------------------------------------------------------
# risk override
# ---------------------------------------------------------------------------

class TestRiskOverride:
    def _setup(self):
        repo.insert_events(pd.DataFrame([_event()]))
        repo.insert_alerts([_alert()])

    def test_valid_override(self):
        self._setup()
        repo.override_risk("ALT-00000001", 90.0, "Known attack", "analyst1")
        a = repo.get_alert("ALT-00000001")
        assert a["risk_score"] == 90.0
        assert a["risk_overridden"] == 1

    def test_override_out_of_range_raises(self):
        self._setup()
        with pytest.raises(ValueError):
            repo.override_risk("ALT-00000001", 110.0, "Too high", "analyst1")

    def test_override_empty_justification_raises(self):
        self._setup()
        with pytest.raises(ValueError):
            repo.override_risk("ALT-00000001", 50.0, "ab", "analyst1")

    def test_risk_history_recorded(self):
        self._setup()
        repo.override_risk("ALT-00000001", 75.0, "Analyst verified", "analyst2")
        hist = repo.get_risk_history("ALT-00000001")
        # Initial insert + override = 2 rows
        assert len(hist) >= 2
        overrides = hist[hist["source"] == "analyst_override"]
        assert len(overrides) == 1


# ---------------------------------------------------------------------------
# audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_audit_entries_created_on_status_change(self):
        repo.insert_events(pd.DataFrame([_event()]))
        repo.insert_alerts([_alert()])
        repo.update_status("ALT-00000001", "Investigating", "alice")
        audit = repo.get_audit("ALT-00000001")
        assert len(audit) >= 1
        assert any(audit["action"] == "status_change")

    def test_audit_entries_created_on_note(self):
        repo.insert_events(pd.DataFrame([_event()]))
        repo.insert_alerts([_alert()])
        repo.add_note("ALT-00000001", "bob", "Noted.")
        audit = repo.get_audit("ALT-00000001")
        assert any(audit["action"] == "note_added")

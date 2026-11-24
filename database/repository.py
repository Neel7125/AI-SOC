"""Data-access layer: events, alerts, lifecycle, notes, evidence, risk history, audit trail."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Iterable

import pandas as pd

import config
from database.connection import init_db, session

log = logging.getLogger(__name__)

ALLOWED_TRANSITIONS = {
    "New": {"Investigating"},
    "Investigating": {"Contained", "Resolved"},
    "Contained": {"Investigating", "Resolved"},
    "Resolved": {"Closed", "Investigating"},
    "Closed": set(),
}
ALERT_COLS = ["alert_id", "event_id", "title", "source", "created_at", "detected_at", "acknowledged_at",
              "responded_at", "timestamp_source", "detection_method", "rule_ids", "rule_names", "ml_model",
              "ml_prediction", "ml_confidence", "anomaly_score", "is_anomaly", "severity", "impact",
              "asset_criticality", "exploitability", "risk_score", "risk_level", "risk_components_json",
              "risk_overridden", "attack_category", "src_ip", "dst_ip", "hostname", "username", "mitre_json",
              "status", "gt_label", "workload", "event_count"]
EVENT_COLS = ["event_id", "timestamp", "source", "event_type", "src_ip", "dst_ip", "dst_port", "protocol",
              "hostname", "username", "process", "command_line", "file_path", "description", "gt_label",
              "gt_category", "features_json"]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _clean(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, float) and pd.isna(v):
        return None
    if hasattr(v, "item"):
        v = v.item()
    if isinstance(v, pd.Timestamp):
        return v.strftime("%Y-%m-%dT%H:%M:%S")
    return v


def reset_db() -> None:
    init_db(reset=True)


def insert_events(df: pd.DataFrame) -> int:
    init_db()
    rows = [tuple(_clean(r.get(c)) for c in EVENT_COLS) for r in df.to_dict("records")]
    with session() as c:
        c.executemany(f"INSERT OR REPLACE INTO events({','.join(EVENT_COLS)}) VALUES({','.join('?' * len(EVENT_COLS))})", rows)
    return len(rows)


def insert_alerts(alerts: Iterable[dict]) -> int:
    init_db()
    rows = [tuple(_clean(a.get(c)) for c in ALERT_COLS) for a in alerts]
    with session() as c:
        c.executemany(f"INSERT OR REPLACE INTO alerts({','.join(ALERT_COLS)}) VALUES({','.join('?' * len(ALERT_COLS))})", rows)
        for a in rows:
            c.execute("INSERT INTO risk_history(alert_id, ts, risk_score, risk_level, source, justification, actor) VALUES(?,?,?,?,?,?,?)",
                      (a[0], now_iso(), a[ALERT_COLS.index('risk_score')], a[ALERT_COLS.index('risk_level')],
                       "calculated", "initial automated score", "system"))
    return len(rows)


def query_df(sql: str, params: tuple = ()) -> pd.DataFrame:
    init_db()
    with session() as c:
        return pd.read_sql_query(sql, c, params=params)


def list_alerts(workload: str | None = None) -> pd.DataFrame:
    if workload:
        return query_df("SELECT * FROM alerts WHERE workload=? ORDER BY risk_score DESC", (workload,))
    return query_df("SELECT * FROM alerts ORDER BY risk_score DESC")


def get_alert(alert_id: str) -> dict | None:
    df = query_df("SELECT * FROM alerts WHERE alert_id=?", (alert_id,))
    return None if df.empty else df.iloc[0].to_dict()


def get_event(event_id: str) -> dict | None:
    df = query_df("SELECT * FROM events WHERE event_id=?", (event_id,))
    return None if df.empty else df.iloc[0].to_dict()


def count_events() -> int:
    return int(query_df("SELECT COUNT(*) n FROM events").iloc[0, 0])


def audit(alert_id: str | None, actor: str, action: str, detail: str = "") -> None:
    with session() as c:
        c.execute("INSERT INTO audit_log(ts, alert_id, actor, action, detail) VALUES(?,?,?,?,?)",
                  (now_iso(), alert_id, actor, action, detail))


def update_status(alert_id: str, new_status: str, actor: str = "analyst") -> None:
    if new_status not in config.INCIDENT_STATUSES:
        raise ValueError(f"Unknown status {new_status}")
    a = get_alert(alert_id)
    if a is None:
        raise KeyError(alert_id)
    old = a["status"]
    if new_status != old and new_status not in ALLOWED_TRANSITIONS[old]:
        raise ValueError(f"Transition {old} -> {new_status} not allowed (allowed: {sorted(ALLOWED_TRANSITIONS[old])})")
    with session() as c:
        c.execute("UPDATE alerts SET status=? WHERE alert_id=?", (new_status, alert_id))
        if new_status == "Investigating" and not a.get("acknowledged_at"):
            c.execute("UPDATE alerts SET acknowledged_at=?, timestamp_source='recorded' WHERE alert_id=?", (now_iso(), alert_id))
        if new_status in ("Contained", "Resolved") and not a.get("responded_at"):
            c.execute("UPDATE alerts SET responded_at=?, timestamp_source='recorded' WHERE alert_id=?", (now_iso(), alert_id))
    audit(alert_id, actor, "status_change", f"{old} -> {new_status}")


def add_note(alert_id: str, author: str, note: str) -> None:
    if not note.strip():
        raise ValueError("Empty note")
    with session() as c:
        c.execute("INSERT INTO notes(alert_id, ts, author, note) VALUES(?,?,?,?)", (alert_id, now_iso(), author, note))
    audit(alert_id, author, "note_added", note[:200])


def add_evidence(alert_id: str, author: str, text: str) -> None:
    if not text.strip():
        raise ValueError("Empty evidence")
    with session() as c:
        c.execute("INSERT INTO evidence(alert_id, ts, author, evidence_text) VALUES(?,?,?,?)", (alert_id, now_iso(), author, text))
    audit(alert_id, author, "evidence_added", text[:200])


def get_notes(alert_id: str) -> pd.DataFrame:
    return query_df("SELECT ts, author, note FROM notes WHERE alert_id=? ORDER BY id", (alert_id,))


def get_evidence(alert_id: str) -> pd.DataFrame:
    return query_df("SELECT ts, author, evidence_text FROM evidence WHERE alert_id=? ORDER BY id", (alert_id,))


def get_audit(alert_id: str | None = None) -> pd.DataFrame:
    if alert_id:
        return query_df("SELECT * FROM audit_log WHERE alert_id=? ORDER BY id", (alert_id,))
    return query_df("SELECT * FROM audit_log ORDER BY id DESC LIMIT 500")


def override_risk(alert_id: str, score: float, justification: str, actor: str = "analyst") -> None:
    from risk_engine.risk_calculator import classify
    if not 0 <= score <= 100:
        raise ValueError("Override score must be within 0-100")
    if len(justification.strip()) < 5:
        raise ValueError("A justification is required to override a risk score")
    level = classify(score)
    with session() as c:
        c.execute("UPDATE alerts SET risk_score=?, risk_level=?, risk_overridden=1 WHERE alert_id=?", (score, level, alert_id))
        c.execute("INSERT INTO risk_history(alert_id, ts, risk_score, risk_level, source, justification, actor) VALUES(?,?,?,?,?,?,?)",
                  (alert_id, now_iso(), score, level, "analyst_override", justification, actor))
    audit(alert_id, actor, "risk_override", f"score={score} justification={justification}")


def get_risk_history(alert_id: str) -> pd.DataFrame:
    return query_df("SELECT ts, risk_score, risk_level, source, justification, actor FROM risk_history WHERE alert_id=? ORDER BY id", (alert_id,))


def set_severity_label(alert_id: str, level: str, actor: str = "analyst") -> None:
    from risk_engine.risk_calculator import LEVEL_MID
    if level not in LEVEL_MID:
        raise ValueError(level)
    override_risk(alert_id, LEVEL_MID[level], f"analyst assigned severity {level}", actor)


def save_investigation(alert_id: str, rec: dict) -> None:
    with session() as c:
        c.execute("""INSERT INTO investigations(alert_id, ts, provider, model, rag_used, response_json, latency_s,
                     prompt_tokens, completion_tokens, cost_usd, valid_json, retrieval_json, warnings_json)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (alert_id, now_iso(), rec["provider"], rec["model"], int(rec["rag_used"]), json.dumps(rec["response"]),
                   rec["latency_s"], rec["prompt_tokens"], rec["completion_tokens"], rec["cost_usd"],
                   int(rec["valid_json"]), json.dumps(rec["retrieval"]), json.dumps(rec["warnings"])))
    audit(alert_id, f"llm:{rec['provider']}", "investigation", f"rag_used={rec['rag_used']} valid_json={rec['valid_json']}")


def get_investigations(alert_id: str | None = None) -> pd.DataFrame:
    if alert_id:
        return query_df("SELECT * FROM investigations WHERE alert_id=? ORDER BY id DESC", (alert_id,))
    return query_df("SELECT * FROM investigations ORDER BY id DESC")


def log_retrieval(query: str, k: int, results: list[dict]) -> None:
    init_db()
    with session() as c:
        c.execute("INSERT INTO retrieval_log(ts, query, k, results_json) VALUES(?,?,?,?)",
                  (now_iso(), query[:500], k, json.dumps(results)))

"""SQLite schema (PostgreSQL-compatible SQL types; SQLite is the implemented backend)."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  event_id TEXT PRIMARY KEY, timestamp TEXT, source TEXT, event_type TEXT,
  src_ip TEXT, dst_ip TEXT, dst_port INTEGER, protocol TEXT, hostname TEXT, username TEXT,
  process TEXT, command_line TEXT, file_path TEXT, description TEXT,
  gt_label INTEGER, gt_category TEXT, features_json TEXT);
CREATE TABLE IF NOT EXISTS alerts(
  alert_id TEXT PRIMARY KEY, event_id TEXT, title TEXT, source TEXT,
  created_at TEXT, detected_at TEXT, acknowledged_at TEXT, responded_at TEXT, timestamp_source TEXT,
  detection_method TEXT, rule_ids TEXT, rule_names TEXT,
  ml_model TEXT, ml_prediction TEXT, ml_confidence REAL, anomaly_score REAL, is_anomaly INTEGER,
  severity REAL, impact REAL, asset_criticality REAL, exploitability REAL,
  risk_score REAL, risk_level TEXT, risk_components_json TEXT, risk_overridden INTEGER DEFAULT 0,
  attack_category TEXT, src_ip TEXT, dst_ip TEXT, hostname TEXT, username TEXT,
  mitre_json TEXT, status TEXT DEFAULT 'New', gt_label INTEGER, workload TEXT, event_count INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, alert_id TEXT, actor TEXT, action TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS notes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, ts TEXT, author TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS evidence(
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, ts TEXT, author TEXT, evidence_text TEXT);
CREATE TABLE IF NOT EXISTS risk_history(
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, ts TEXT, risk_score REAL, risk_level TEXT,
  source TEXT, justification TEXT, actor TEXT);
CREATE TABLE IF NOT EXISTS investigations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT, ts TEXT, provider TEXT, model TEXT, rag_used INTEGER,
  response_json TEXT, latency_s REAL, prompt_tokens INTEGER, completion_tokens INTEGER, cost_usd REAL,
  valid_json INTEGER, retrieval_json TEXT, warnings_json TEXT);
CREATE TABLE IF NOT EXISTS retrieval_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, query TEXT, k INTEGER, results_json TEXT);
CREATE INDEX IF NOT EXISTS idx_alert_risk ON alerts(risk_score);
CREATE INDEX IF NOT EXISTS idx_alert_status ON alerts(status);
"""

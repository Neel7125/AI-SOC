"""Central configuration for the AI-SOC. Secrets come only from environment / .env (never hardcoded)."""
from __future__ import annotations

import logging
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

# ---- Directories -----------------------------------------------------------
DATA_DIR = ROOT / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"
SYNTH_DIR = DATA_DIR / "synthetic"
SAMPLES_DIR = DATA_DIR / "samples"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
MODELS_DIR = ROOT / "models"
RESULTS_DIR = ROOT / "results"
ML_EVAL_DIR = RESULTS_DIR / "ml_evaluation"
LLM_EVAL_DIR = RESULTS_DIR / "llm_evaluation"
SOC_CMP_DIR = RESULTS_DIR / "soc_comparison"
REPORTS_DIR = RESULTS_DIR / "reports"
SPL_DIR = ROOT / "siem" / "spl_queries"
SIGMA_DIR = ROOT / "siem" / "detection_rules"

for _d in (RAW_DIR, PROCESSED_DIR, SYNTH_DIR, SAMPLES_DIR, KNOWLEDGE_DIR, MODELS_DIR,
           ML_EVAL_DIR, LLM_EVAL_DIR, SOC_CMP_DIR, REPORTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

DB_PATH = Path(os.getenv("SOC_DB_PATH", str(DATA_DIR / "soc.db")))

# ---- Logging ---------------------------------------------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"),
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# ---- Datasets (set paths in .env or edit here; nothing is auto-downloaded) --
DATASETS: dict[str, dict] = {
    "synthetic": {
        "path": str(SYNTH_DIR / "train_flows.csv"), "type": "network_flow",
        "label_col": "attack_category", "benign_label": "BENIGN",
        "drop_cols": ["flow_id", "timestamp", "src_ip", "dst_ip", "hostname", "username", "is_malicious"],
    },
    "cic-ids2017": {
        "path": os.getenv("CICIDS2017_PATH", str(RAW_DIR / "CIC-IDS2017.csv")), "type": "network_flow",
        "label_col": "Label", "benign_label": "BENIGN",
        "drop_cols": ["Flow ID", "Source IP", "Destination IP", "Timestamp", "Source Port"],
    },
    "cse-cic-ids2018": {
        "path": os.getenv("CICIDS2018_PATH", str(RAW_DIR / "CSE-CIC-IDS2018.csv")), "type": "network_flow",
        "label_col": "Label", "benign_label": "Benign",
        "drop_cols": ["Flow ID", "Src IP", "Dst IP", "Timestamp", "Src Port"],
    },
    "unsw-nb15": {
        "path": os.getenv("UNSWNB15_PATH", str(RAW_DIR / "UNSW-NB15.csv")), "type": "network_flow",
        "label_col": "attack_cat", "benign_label": "Normal",
        "drop_cols": ["id", "srcip", "dstip", "label", "stime", "ltime"],
    },
    # BETH is endpoint (process) telemetry: different schema, deliberately NOT mixed with flow data.
    "beth": {
        "path": os.getenv("BETH_PATH", str(RAW_DIR / "beth.csv")), "type": "endpoint_event",
        "label_col": "sus_label", "benign_label": "0", "drop_cols": ["timestamp", "processName", "hostName", "args"],
    },
}
ACTIVE_DATASET = os.getenv("ACTIVE_DATASET", "synthetic")

# ---- Risk scoring (all inputs normalised to 0-100) --------------------------
RISK_WEIGHTS = {"severity": 0.30, "impact": 0.25, "ml_confidence": 0.20,
                "asset_criticality": 0.15, "exploitability": 0.10}
RISK_LEVELS = [(20, "Informational"), (40, "Low"), (60, "Medium"), (80, "High"), (100, "Critical")]
CONTEXT_MAX_BONUS = 10.0          # cap of optional contextual adjustment (points)
ALERT_RISK_THRESHOLD = float(os.getenv("ALERT_RISK_THRESHOLD", "35"))  # combined AI-SOC alert gate
ML_THRESHOLD = float(os.getenv("ML_THRESHOLD", "0.5"))

# ---- LLM -------------------------------------------------------------------
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "offline")   # offline | openai | ollama
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.1")
# USD per 1M tokens (input, output) used ONLY for cost estimation; edit to current pricing.
LLM_PRICES = {"gpt-4o-mini": (0.15, 0.60), "gpt-4o": (2.50, 10.00)}

# ---- RAG -------------------------------------------------------------------
EMBEDDING_BACKEND = os.getenv("EMBEDDING_BACKEND", "tfidf")   # tfidf | sbert
SBERT_MODEL = os.getenv("SBERT_MODEL", "all-MiniLM-L6-v2")
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "4"))
RAG_MIN_SCORE = float(os.getenv("RAG_MIN_SCORE", "0.05"))

# ---- Splunk (optional) -----------------------------------------------------
SPLUNK_HOST = os.getenv("SPLUNK_HOST", "")
SPLUNK_PORT = int(os.getenv("SPLUNK_PORT", "8089"))
SPLUNK_TOKEN = os.getenv("SPLUNK_TOKEN", "")
SPLUNK_USER = os.getenv("SPLUNK_USER", "")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "")
SPLUNK_VERIFY_TLS = os.getenv("SPLUNK_VERIFY_TLS", "false").lower() == "true"

# ---- SOC simulation assumptions (clearly labelled as ASSUMPTIONS in reports) -
SOC_SIM = {
    "analysts": 2,                 # analysts working in parallel
    "triage_minutes": 8.0,         # baseline investigation time per alert (assumption)
    "llm_time_factor": 0.60,       # investigation time multiplier when LLM summary is available (assumption)
    "ack_sla_minutes": 15.0, "respond_sla_minutes": 240.0,
    "response_minutes": 20.0,
}
INCIDENT_STATUSES = ["New", "Investigating", "Contained", "Resolved", "Closed"]

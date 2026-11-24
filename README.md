# 🛡️ AI-Driven Security Operations Centre (AI-SOC)

A research-grade, fully operational prototype of an AI-augmented Security Operations Centre — combining rule-based detection, supervised ML classification, unsupervised anomaly detection, LLM-powered incident investigation (with RAG), quantitative risk scoring, and an interactive 14-page Streamlit dashboard.

> **All data is synthetic.** Every metric and chart is generated locally from synthetic network flows. No real credentials or production systems are required to run the demo.

---

## ✨ Key Features

| Component | Technology |
|---|---|
| Supervised threat detection | Random Forest · XGBoost · Logistic Regression |
| Anomaly detection | Isolation Forest (benign-only training) |
| LLM incident investigation | Ollama (llama3.1) · OpenAI · offline template |
| Retrieval-Augmented Generation | FAISS + SBERT `all-MiniLM-L6-v2` |
| Risk scoring | Weighted 5-component model (0–100 scale) |
| MITRE ATT&CK mapping | Curated technique knowledge base + validation |
| Dashboard | Streamlit · 14 interactive pages · dark theme |
| REST API | FastAPI · 13 endpoints |
| SIEM integration | Splunk Enterprise (REST API) |
| Database | SQLite · 8 tables · full audit trail |
| Tests | 131 unit + integration tests (pytest) |

---

## 📊 Experiment Results (Synthetic Benchmark)

### ML Classification — Held-Out Test Set (1,823 flows)

| Model | Precision | Recall | F1 | AUC-ROC |
|---|---|---|---|---|
| **Random Forest ★** | 0.900 | 0.969 | 0.933 | 0.991 |
| XGBoost | 0.915 | 0.955 | 0.935 | 0.993 |
| Logistic Regression | 0.786 | 0.995 | 0.878 | 0.989 |
| Isolation Forest | 0.807 | 0.580 | 0.675 | 0.870 |

★ Selected as production model (best validation macro-F1 = 0.9543)

### SOC Configuration Comparison — Live Workload (4,147 flows)

| Config | Description | Recall | F1 | MTTA (min) | Avg Investigation (min) |
|---|---|---|---|---|---|
| A | Rules only | 64.6% | 0.732 | 1.054 | 8.0 |
| B | Rules + ML | **97.7%** | **0.923** | 2.923 | 8.0 |
| C | Rules + LLM | 64.6% | 0.732 | **0.383** | **4.8** |
| D | Combined AI-SOC | **97.8%** | 0.911 | 0.975 | **4.8** |

**Config D** achieves the best overall balance: 97.8% recall, 40% faster investigations, 100% ACK SLA compliance.

### LLM Evaluation (9 test cases, Ollama llama3.1 + RAG)

| Metric | ollama+RAG |
|---|---|
| JSON valid | 1.000 |
| Faithfulness (evidence grounding) | 0.958 |
| Hallucinated | **0.000** |
| Recommendation keyword coverage | **0.889** |
| Prompt injection detection rate | **100%** |

---

## 🗂️ Project Structure

```
ai_soc_demo/
├── app.py                      # Streamlit entry point  →  streamlit run app.py
├── config.py                   # Central configuration (reads .env)
├── requirements.txt
├── .env.example                # Copy to .env, fill in credentials
│
├── api/                        # FastAPI REST backend  →  uvicorn api.main:app --reload
│   └── main.py
│
├── dashboard/                  # One module per Streamlit page (14 pages)
│   ├── common.py               # Shared CSS, helpers, global filters
│   ├── overview.py             # SOC Overview KPIs
│   ├── monitoring.py           # Live stream ingestion
│   ├── alerts.py               # Alert management + lifecycle
│   ├── investigation.py        # AI incident investigation (LLM + RAG)
│   ├── ml_analytics.py         # ML detection + anomaly + evaluation
│   ├── llm_analytics.py        # LLM evaluation results
│   ├── mitre.py                # MITRE ATT&CK explorer
│   ├── risk.py                 # Risk assessment + calculator
│   ├── reports.py              # Incident + academic reports
│   ├── soc_perf.py             # SOC metrics + A/B/C/D comparison
│   └── system.py               # System config + setup trigger
│
├── database/                   # SQLite data layer
│   ├── connection.py
│   ├── models.py               # 8-table schema
│   └── repository.py           # CRUD, state machine, audit trail
│
├── detection/                  # Threat detection pipeline
│   ├── rule_engine.py          # 9 Sigma-style rules (NET/EP)
│   ├── correlation.py          # Time-window aggregates
│   ├── alert_processor.py      # Scoring, grouping, incident creation
│   └── pipeline.py             # Orchestration + streaming
│
├── evaluation/                 # Evaluation framework
│   ├── classification_metrics.py
│   ├── ml_evaluation.py        # ML artefacts (charts, metrics)
│   ├── llm_evaluation.py       # LLM metrics (faithfulness, hallucination…)
│   ├── comparison.py           # Traditional vs AI SOC experiment
│   └── soc_metrics.py          # MTTD/MTTA/MTTR, SLA, queue simulation
│
├── ingestion/                  # Log ingestion & normalisation
│   ├── synthetic.py            # Synthetic data generator
│   ├── normalizer.py
│   ├── csv_loader.py
│   ├── linux_parser.py
│   ├── sysmon_parser.py
│   └── zeek_parser.py
│
├── llm_engine/                 # LLM investigation
│   ├── investigation.py        # Main workflow + guardrail layer
│   ├── llm_provider.py         # Provider abstraction + offline template
│   ├── ollama_client.py        # Ollama with JSON schema enforcement
│   ├── openai_client.py
│   ├── prompts.py              # Prompt construction + injection defence
│   └── response_schema.py      # Pydantic validation schema
│
├── ml_engine/                  # ML models
│   ├── train.py                # Training pipeline
│   ├── predict.py              # Inference only
│   ├── preprocessing.py        # Splits, imputation, encoding, scaling
│   ├── model_registry.py       # Artifact metadata + best-model selection
│   ├── random_forest.py
│   ├── xgboost_model.py
│   ├── logistic_regression.py
│   └── isolation_forest.py
│
├── mitre/                      # MITRE ATT&CK
│   ├── knowledge_base.py
│   └── attack_mapping.py
│
├── rag/                        # Retrieval-Augmented Generation
│   ├── retriever.py            # build_index(), retrieve()
│   ├── embeddings.py           # TF-IDF or SBERT backends
│   ├── vector_store.py         # FAISS-backed index
│   ├── chunker.py
│   └── document_loader.py
│
├── risk_engine/
│   ├── risk_calculator.py      # Weighted scoring + context adjustment
│   └── severity.py
│
├── reporting/
│   ├── incident_report.py      # JSON + PDF incident reports
│   └── academic_report.py      # Experiment summary report
│
├── siem/
│   ├── splunk_client.py        # Splunk Enterprise REST client + fallback
│   └── spl_queries/            # 6 SPL detection queries
│
├── scripts/
│   ├── setup_demo.py           # ⭐ One-shot full setup (7 steps)
│   ├── run_pipeline.py         # Detection pipeline runner
│   ├── train_all.py
│   ├── evaluate_all.py
│   └── run_experiments.py
│
├── tests/                      # 131 tests (pytest)
│   ├── conftest.py
│   ├── test_risk_engine.py
│   ├── test_classification_metrics.py
│   ├── test_rule_engine.py
│   ├── test_database.py
│   ├── test_soc_metrics.py
│   ├── test_llm_pipeline.py
│   └── test_pipeline_integration.py
│
└── data/
    ├── knowledge/              # RAG source documents
    ├── synthetic/              # Generated log files
    ├── samples/                # LLM eval set, threat intel
    └── soc.db                  # SQLite database
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.10+
- [Ollama](https://ollama.com/download) (for local LLM — optional, offline mode works without it)
- Git

### 1. Clone the repository

```bash
git clone https://github.com/nillptl001/AI-SOC.git
cd AI-SOC
```

### 2. Create virtual environment and install dependencies

```bash
python -m venv .venv

# Windows
.\.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate

pip install -r requirements.txt
```

### 3. Configure environment

```bash
copy .env.example .env     # Windows
cp .env.example .env       # macOS/Linux
```

Edit `.env` — the **minimum** to get started (offline mode, no credentials needed):

```env
LLM_PROVIDER=offline
ACTIVE_DATASET=synthetic
EMBEDDING_BACKEND=tfidf
```

### 4. Run one-shot setup

This generates synthetic data, trains all models, runs the detection pipeline, builds the RAG index, runs LLM/SOC evaluations, and produces the academic report (~2 minutes):

```bash
python scripts/setup_demo.py
```

Expected output:
```
1/7 generating SYNTHETIC data  → {'train_flows': 12152, 'live_flows': 4147, ...}
2/7 training models (RF, XGBoost, LR, Isolation Forest)
3/7 ML evaluation charts/metrics
4/7 detection pipeline -> database
5/7 building RAG index
6/7 LLM evaluation + SOC comparison
7/7 academic report
DONE
```

### 5. Launch the dashboard

```bash
streamlit run app.py
```

Browser opens at **http://localhost:8501**

### 6. (Optional) Launch the REST API

In a second terminal:

```bash
uvicorn api.main:app --reload
```

API docs at **http://localhost:8000/docs**

---

## ⚙️ Configuration

All settings live in `.env` (copy from `.env.example`). Key variables:

### LLM Provider

**Option A — Offline (default, no credentials, works immediately)**
```env
LLM_PROVIDER=offline
```

**Option B — Ollama (local LLM, free, no data leaves your machine)**
```env
LLM_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```
Install Ollama from https://ollama.com, then: `ollama pull llama3.1`

**Option C — OpenAI**
```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...
OPENAI_MODEL=gpt-4o-mini
```

### RAG / Embeddings

```env
EMBEDDING_BACKEND=tfidf    # offline, no install needed
# or
EMBEDDING_BACKEND=sbert    # semantic search (pip install sentence-transformers)
SBERT_MODEL=all-MiniLM-L6-v2
```

### Splunk Enterprise (optional)

```env
SPLUNK_HOST=your-splunk-host-or-ip
SPLUNK_PORT=8089
SPLUNK_TOKEN=your-bearer-token    # Settings → Tokens → New Token
SPLUNK_VERIFY_TLS=false
```

The app falls back to local CSV files automatically when Splunk is not configured.

### Real Datasets (optional)

The demo runs fully on synthetic data. To train on real datasets:

```env
ACTIVE_DATASET=cic-ids2017
CICIDS2017_PATH=data/raw/CIC-IDS2017.csv
```

Supported: `cic-ids2017`, `cse-cic-ids2018`, `unsw-nb15`, `beth`

---

## 🖥️ Dashboard Pages

| Page | Description |
|---|---|
| **SOC Overview** | KPI metrics, incident timeline, risk distribution charts |
| **Live Security Monitoring** | Batch/stream ingestion, real-time scatter plot |
| **Alert Management** | Full lifecycle: status, notes, evidence, risk override, audit trail |
| **AI Incident Investigation** | Evidence-grounded LLM analysis, RAG docs, analyst Q&A |
| **ML Threat Detection** | Model registry, prediction histograms, live classifier |
| **Anomaly Detection** | Isolation Forest distribution, threshold slider, explainability |
| **Risk Assessment** | Interactive calculator with configurable weights |
| **MITRE ATT&CK Explorer** | Coverage treemap, technique browser, incident mapping |
| **ML Model Evaluation** | Confusion matrices, ROC/PR curves, feature importance |
| **LLM Evaluation** | Faithfulness, hallucination, latency, token usage |
| **SOC Performance Analytics** | MTTD/MTTA/MTTR, SLA compliance |
| **Traditional vs AI SOC** | Config A/B/C/D comparison, threshold sweep |
| **Incident Reports** | JSON/PDF download, academic report builder |
| **System Configuration** | Setup trigger, LLM status, Splunk config, dataset paths |

---

## 🔌 REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | System health, model status |
| GET | `/alerts` | List alerts (filter: risk, status, limit) |
| GET | `/alerts/{id}` | Alert detail |
| POST | `/alerts/{id}/status` | Change incident status |
| POST | `/alerts/{id}/notes` | Add analyst note |
| POST | `/alerts/{id}/override-risk` | Override risk score |
| POST | `/predict` | ML prediction for a single flow |
| POST | `/investigate/{id}` | LLM investigation |
| POST | `/ask` | RAG-grounded analyst Q&A |
| GET | `/rag/search` | Knowledge-base search |
| POST | `/risk/calculate` | Risk score calculation |
| GET | `/metrics/soc` | SOC operational metrics |
| GET | `/reports/{id}.{json\|pdf}` | Download incident report |

---

## 🧪 Running Tests

```bash
# Fast unit tests only (~5 seconds)
pytest tests/ -m "not integration" -v

# All tests including slow end-to-end pipeline test
pytest tests/ -v

# With coverage report
pip install pytest-cov
pytest tests/ -m "not integration" --cov=. --cov-report=term-missing
```

131 tests across 7 files covering: risk engine, classification metrics, detection rules, database layer, SOC metrics, LLM pipeline, and full pipeline integration.

---

## 🏗️ Architecture Overview

```
Synthetic Data
     │
     ▼
Ingestion Layer  (csv_loader · sysmon_parser · linux_parser · zeek_parser)
     │
     ▼
Detection Pipeline
  ├── Rule Engine      (NET-001..004 · EP-001..005)
  ├── ML Classifier    (Random Forest / XGBoost / Logistic Regression)
  ├── Isolation Forest (anomaly detection, benign-only trained)
  └── Risk Engine      (0.30×Severity + 0.25×Impact + 0.20×MLConf + ...)
     │
     ▼
SQLite Database  (events · alerts · audit_log · investigations · ...)
     │
     ├── Streamlit Dashboard  (14 pages)
     │       └── AI Incident Investigation
     │               ├── FAISS/SBERT RAG retrieval
     │               ├── LLM (Ollama / OpenAI / offline)
     │               └── Guardrail layer (grounding · MITRE · human approval)
     │
     └── FastAPI REST API  (13 endpoints)
```

---

## 🔒 Security Design Principles

- **No automatic actions**: all recommended remediations require explicit analyst approval
- **Evidence grounding**: every LLM claim must cite `[E1]`–`[E8]` evidence references
- **Prompt injection defence**: 11-pattern scan of all alert free-text fields before prompting
- **MITRE validation**: LLM technique suggestions validated against knowledge base
- **Full audit trail**: every status change, note, evidence addition, and risk override is logged
- **Secrets from environment only**: no credentials ever hardcoded

---

## 📋 Risk Formula

```
Risk Score (0–100) =
    0.30 × Severity
  + 0.25 × Impact
  + 0.20 × ML_Confidence
  + 0.15 × Asset_Criticality
  + 0.10 × Exploitability
  + context_adjustment (capped at +10)

Context adjustment sources: CVSS · EPSS · Threat-Intel reputation ·
                            Prior recurrence count · High-impact MITRE tactic

Risk Levels: 0–20 Informational | 21–40 Low | 41–60 Medium | 61–80 High | 81–100 Critical
```

---

## ⚠️ Limitations

- All results are from **synthetic data** — not real network traffic
- SOC queue metrics (MTTD/MTTA/MTTR) are **simulated** with assumed parameters
- LLM evaluation covers **9 hand-curated cases** — illustrative, not statistically powered
- Local Ollama inference averages **~92 seconds/investigation on CPU** (GPU or OpenAI API reduces this to 2–5 s)
- No production hardening (authentication, rate limiting, TLS termination)

---

## 📄 License

This project is a course project / research prototype for educational purposes.

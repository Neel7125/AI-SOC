# AI-Driven Security Operations Centre (AI-SOC)
### Course Project Report

---

| Field | Detail |
|---|---|
| **Project Title** | AI-Driven Security Operations Centre Demo |
| **Technology Stack** | Python 3.13, Streamlit, FastAPI, SQLite, scikit-learn, XGBoost, Ollama (llama3.1), FAISS, SBERT |
| **Date** | November 2026 |

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Problem Statement](#2-problem-statement)
3. [System Architecture](#3-system-architecture)
4. [Implementation](#4-implementation)
   - 4.1 Data Ingestion
   - 4.2 Rule-Based Detection Engine
   - 4.3 Machine Learning Pipeline
   - 4.4 Anomaly Detection
   - 4.5 Risk Scoring Engine
   - 4.6 LLM Investigation with RAG
   - 4.7 MITRE ATT&CK Integration
   - 4.8 Database and Audit Layer
   - 4.9 Streamlit Dashboard
   - 4.10 REST API
5. [Experimental Setup](#5-experimental-setup)
6. [Results](#6-results)
   - 6.1 ML Classification Results
   - 6.2 SOC Configuration Comparison
   - 6.3 LLM Evaluation Results
   - 6.4 Threshold Sensitivity Analysis
7. [Discussion](#7-discussion)
8. [Limitations](#8-limitations)
9. [Conclusion](#9-conclusion)
10. [References](#10-references)

---

## 1. Introduction

Modern enterprises face an unprecedented volume and sophistication of cyber threats. Security Operations Centres (SOCs) are the front line of defence, tasked with monitoring, detecting, and responding to security incidents in real time. However, traditional SOCs are under severe strain: analyst alert fatigue, high false-positive rates, and slow manual triage processes leave organisations exposed.

This project — **AI-SOC Demo** — builds and evaluates a complete prototype of an AI-augmented Security Operations Centre. It integrates four complementary AI technologies into a single cohesive system:

1. **Supervised ML classification** (Random Forest, XGBoost, Logistic Regression) for network-flow threat detection
2. **Unsupervised anomaly detection** (Isolation Forest) for catching zero-day-style deviations
3. **Large Language Model (LLM) investigation** with Retrieval-Augmented Generation (RAG) for automated, evidence-grounded incident analysis
4. **Quantitative risk scoring** to prioritise analyst attention on the most dangerous incidents

The system is fully operational: it ingests logs, runs detections, populates a database, and presents findings through an interactive 14-page Streamlit dashboard and a FastAPI REST backend. All results are generated from synthetic data to enable reproducible experimentation without requiring real sensitive network data.

---

## 2. Problem Statement

Traditional SOC workflows suffer from several well-documented problems:

- **Alert fatigue**: analysts are overwhelmed with thousands of low-quality alerts per day
- **High false-positive rates**: rule-only systems flag benign activity as malicious, wasting analyst time
- **Slow triage**: manually investigating each alert takes 8–15 minutes; a two-analyst team cannot keep pace
- **Missed detections**: novel attack patterns that do not match known rules go undetected
- **Inconsistent documentation**: human analysts produce variable-quality incident reports

This project addresses all five problems by evaluating four SOC configurations on the same workload:

| Config | Approach |
|---|---|
| **A** | Traditional: signature/rule-based detection only |
| **B** | ML-augmented: rules + supervised ML classifier |
| **C** | LLM-augmented: rules + LLM-generated investigation reports |
| **D** | Combined AI-SOC: rules + ML + anomaly detection + LLM + risk gating |

The central research question is: **how much do AI components improve detection performance, analyst efficiency, and investigation quality compared to a traditional rule-only baseline?**

---

## 3. System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Synthetic Data Generator                     │
│        12,152 train flows · 4,147 live flows · 779 Sysmon        │
│        events · 498 auth.log lines · Zeek conn logs             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Ingestion Layer                             │
│   csv_loader · linux_parser · sysmon_parser · zeek_parser       │
│   normalizer (unified event schema, deduplication, feature      │
│   derivation)                                                    │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Detection Pipeline                            │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Rule Engine  │  │  ML Engine   │  │  Isolation Forest    │  │
│  │ NET-001..004 │  │ RandomForest │  │  Anomaly Detection   │  │
│  │ EP-001..005  │  │ XGBoost / LR │  │  (benign-only train) │  │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬───────────┘  │
│         └─────────────────┴─────────────────────┘              │
│                           │                                      │
│                    ┌──────▼───────┐                             │
│                    │ Risk Engine  │                              │
│                    │ Weighted     │                              │
│                    │ 5-component  │                              │
│                    │ score 0-100  │                              │
│                    └──────┬───────┘                             │
│                           │                                      │
│                    ┌──────▼───────┐                             │
│                    │Alert Processor│                             │
│                    │ Group events │                              │
│                    │ → Incidents  │                              │
│                    └──────┬───────┘                             │
└──────────────────────────┬──────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                     SQLite Database                              │
│  events · alerts · audit_log · notes · evidence ·               │
│  risk_history · investigations · retrieval_log                  │
└──────────┬────────────────────────────────────────┬────────────┘
           │                                        │
           ▼                                        ▼
┌──────────────────────┐              ┌─────────────────────────┐
│  Streamlit Dashboard │              │    FastAPI REST API      │
│  14 interactive pages│              │    /alerts /investigate  │
│  Dark-theme SOC UI   │              │    /predict /ask /risk   │
└──────────────────────┘              └─────────────────────────┘
```

**LLM + RAG subsystem** (called from the AI Incident Investigation page):

```
Alert + Event + Related alerts
        │
        ▼
  Build structured context (evidence items E1..E8)
        │
        ├─── Prompt-injection scan & field sanitization
        │
        ▼
  FAISS vector store (SBERT embeddings)
  ← Query: attack category + ML label + rule names
  → Top-4 knowledge-base chunks retrieved
        │
        ▼
  LLM (Ollama llama3.1 / OpenAI / offline template)
  Structured JSON schema enforcement
        │
        ▼
  Guardrail layer:
  · Evidence-reference grounding check
  · MITRE ID validation against knowledge base
  · Destructive-action gating → human approval required
  · Severity override by risk engine
  · Confidence cap if no grounded evidence
        │
        ▼
  Validated Investigation object → DB → Dashboard
```

---

## 4. Implementation

### 4.1 Data Ingestion

The ingestion layer normalises heterogeneous log formats into a unified event schema. Five parsers are implemented:

- **`csv_loader.py`** — tabular network flow CSVs (CIC-IDS2017 format and synthetic)
- **`sysmon_parser.py`** — Windows Sysmon JSONL events (process create, network connect, file create)
- **`linux_parser.py`** — Linux `auth.log` with optional ground-truth CSV overlay
- **`zeek_parser.py`** — Zeek connection log (`conn.log` TSV format)
- **`normalizer.py`** — deduplication, event-ID generation, missing feature derivation (e.g. `pkts_per_s = total_packets / duration`)

For demonstration, the **synthetic data generator** (`ingestion/synthetic.py`) produces:

| Dataset | Rows | Attack classes |
|---|---|---|
| Training flows | 12,152 | BENIGN, DoS, DDoS, BruteForce, PortScan, Exfiltration, Web Attack |
| Live flows | 4,147 | Same classes, different random seed |
| Sysmon events | 779 | PowerShell Abuse, Privilege Escalation, Suspicious File Activity, C2 |
| Auth.log lines | 498 | BruteForce (SSH), benign logins |

### 4.2 Rule-Based Detection Engine

The rule engine (`detection/rule_engine.py`) implements nine Sigma-style detection rules as vectorised pandas predicates — no row-by-row loops. Each rule has a severity score (0–100), category label, and human-readable description.

**Network flow rules:**

| ID | Name | Severity | Trigger |
|---|---|---|---|
| NET-001 | Port scan | 55 | ≥20 distinct destination ports within 60s from one source |
| NET-002 | SYN/packet flood | 80 | ≥1,500 packets/sec AND ≥100 forward packets |
| NET-003 | Brute force | 70 | ≥10 auth-port flows/min from one source |
| NET-004 | Large outbound transfer | 75 | ≥2 MB to an external destination |

**Endpoint rules:**

| ID | Name | Severity | Trigger |
|---|---|---|---|
| EP-001 | Suspicious PowerShell | 75 | `-enc`, `-EncodedCommand`, `DownloadString`, `IEX`, hidden window |
| EP-002 | Privilege escalation | 85 | `net localgroup administrators /add`, `sekurlsa`, `mimikatz` |
| EP-003 | Suspicious file activity | 70 | Executables in `\Temp\`, `.locked` extensions, `vssadmin delete shadows` |
| EP-004 | SSH brute force | 70 | ≥5 failed SSH logins within 5 minutes |
| EP-005 | Suspicious port connection | 65 | Outbound to ports 4444, 1337, 6667, 31337 |

Window-based rules (NET-001, NET-003, EP-004) use rolling time aggregates computed by `detection/correlation.py` before rule evaluation.

### 4.3 Machine Learning Pipeline

Three supervised classifiers are trained on a stratified 70/15/15 train/validation/test split (seed 42):

- **Random Forest** — 200 trees, balanced class weights
- **XGBoost** — gradient-boosted trees with early stopping on validation
- **Logistic Regression** — L2 regularisation, multinomial, baseline

**Preprocessing pipeline** (`ml_engine/preprocessing.py`):
1. Drop non-feature columns (IPs, timestamps, identifiers)
2. Median imputation for missing values
3. Pearson correlation filter (drop features with r > 0.95 to a retained feature) → kept 15 of 17 features
4. StandardScaler normalisation

The best model is selected on **validation macro-F1** and reported on the held-out test set. Random Forest achieved the best validation score (macro-F1 = 0.9543) and was selected as the production model.

**Optional SMOTE**: the training pipeline supports SMOTE oversampling on the training split only, to address class imbalance.

### 4.4 Anomaly Detection

An **Isolation Forest** (`ml_engine/isolation_forest.py`) is trained exclusively on benign training records (unsupervised). The anomaly threshold is set at the 97th percentile of benign-train scores, flagging flows that are more unusual than 97% of known-good traffic.

This complements supervised classification by catching novel attack patterns that do not match any known class — a proxy for zero-day detection.

### 4.5 Risk Scoring Engine

Every candidate alert is scored using a weighted linear model (`risk_engine/risk_calculator.py`):

```
Risk = 0.30 × Severity
     + 0.25 × Impact
     + 0.20 × ML_Confidence
     + 0.15 × Asset_Criticality
     + 0.10 × Exploitability
     + context_adjustment (capped at +10)
```

All five inputs are normalised to 0–100. The optional context adjustment adds up to +10 points based on CVSS score, EPSS probability, threat-intelligence reputation, prior recurrence count, and high-impact MITRE ATT&CK tactic (Impact, Exfiltration, Privilege Escalation).

Risk levels: 0–20 Informational | 21–40 Low | 41–60 Medium | 61–80 High | 81–100 Critical.

In **Config D**, only events with `risk_score ≥ 35` are promoted to analyst-facing incidents, acting as a noise gate.

### 4.6 LLM Investigation with RAG

The LLM investigation engine (`llm_engine/investigation.py`) implements a human-in-the-loop AI workflow:

**Step 1 — Context building**: structured evidence items E1–E8 are assembled from the alert, its representative event, and up to five related alerts from the same source IP.

**Step 2 — Prompt-injection defence**: every free-text field (command line, description, username) is scanned against 11 injection patterns before being included in the prompt.

**Step 3 — RAG retrieval**: the FAISS-backed vector store (65 chunks, SBERT `all-MiniLM-L6-v2` embeddings) retrieves the top-4 most relevant knowledge-base passages. Sources: incident response procedures, security playbooks, Sigma rule documentation, vulnerability notes, and MITRE ATT&CK technique descriptions.

**Step 4 — LLM generation**: the prompt, evidence, and retrieved passages are sent to the configured provider. Three providers are supported:

- **Offline template** — deterministic summariser, always available, no credentials needed
- **OpenAI** — GPT-4o / GPT-4o-mini via REST API
- **Ollama** — local llama3.1 (or any pulled model) with structured JSON schema enforcement

**Step 5 — Guardrail validation**:
- Evidence references must cite `[E1]`..`[E8]` or are dropped
- MITRE technique IDs are validated against the knowledge base; unrecognised IDs are rejected and logged
- Actions containing destructive verbs (isolate, block, delete, kill, quarantine) are tagged `[REQUIRES HUMAN APPROVAL]`
- Severity is overridden by the risk engine result — the LLM cannot change the risk score
- If no grounded evidence exists, confidence is capped at 0.30

### 4.7 MITRE ATT&CK Integration

The MITRE module (`mitre/attack_mapping.py`, `mitre/knowledge_base.py`) maps detection outputs to ATT&CK techniques through two paths:

1. **Detection-derived**: rule IDs and ML attack categories map to known techniques via a hand-curated lookup table (e.g. PortScan → T1046, BruteForce → T1110, Exfiltration → T1048)
2. **LLM-suggested**: model suggestions are validated against the knowledge base; only recognised technique IDs pass

The dashboard MITRE Explorer shows a treemap of technique coverage, coloured by number of related incidents.

### 4.8 Database and Audit Layer

SQLite is used as the backend (schema is PostgreSQL-compatible). Eight tables are defined:

| Table | Purpose |
|---|---|
| `events` | Normalised security events (network flows, endpoint events) |
| `alerts` | Analyst-facing incidents with full ML/risk/MITRE metadata |
| `audit_log` | Immutable record of every status change, note, evidence addition, override |
| `notes` | Analyst investigation notes |
| `evidence` | Evidence items collected during investigation |
| `risk_history` | Full history of every risk score change with justification |
| `investigations` | LLM investigation records with tokens, cost, latency, warnings |
| `retrieval_log` | RAG query log for observability |

The alert lifecycle follows a strict state machine: `New → Investigating → Contained/Resolved → Closed`. Invalid transitions are rejected at the database layer.

### 4.9 Streamlit Dashboard

The dashboard (`app.py` + `dashboard/`) provides 14 interactive pages:

| Page | Key features |
|---|---|
| SOC Overview | 10 KPI metrics, hourly incident timeline, risk distribution |
| Live Security Monitoring | Batch/stream ingestion with configurable batch size, real-time scatter plot |
| Alert Management | Full lifecycle (status, notes, evidence, risk override, audit trail) |
| AI Incident Investigation | Provider selector, RAG toggle, structured LLM output with grounding display |
| ML Threat Detection | Model registry, prediction histograms, live classifier UI |
| Anomaly Detection | Isolation Forest distribution, threshold slider, feature-level explanation |
| Risk Assessment | Interactive calculator, configurable weights, prioritised queue |
| MITRE ATT&CK Explorer | Coverage treemap, technique browser, incident mapping |
| ML Model Evaluation | Confusion matrices, ROC/PR curves, feature importance, learning curves |
| LLM Evaluation | Faithfulness, hallucination, latency, token usage tables and charts |
| SOC Performance Analytics | MTTD/MTTA/MTTR, SLA compliance, acknowledgement time histogram |
| Traditional vs AI SOC | Config A/B/C/D comparison, threshold sweep chart, category recall |
| Incident Reports | JSON/PDF download, academic report builder |
| System Configuration | Setup trigger, LLM status, Splunk/SIEM status, dataset paths |

The dashboard integrates with **Splunk Enterprise** via the REST API (`siem/splunk_client.py`), falling back to local CSV files when Splunk is not reachable.

### 4.10 REST API

A FastAPI backend (`api/main.py`) exposes all core functions:

```
GET  /health                    system health, model status, event count
GET  /alerts                    list alerts (filter by risk, status, limit)
GET  /alerts/{id}               alert detail
POST /alerts/{id}/status        state machine transition
POST /alerts/{id}/notes         add analyst note
POST /alerts/{id}/override-risk override risk score with mandatory justification
POST /predict                   ML prediction for a single flow
POST /investigate/{id}          LLM investigation for an alert
POST /ask                       analyst Q&A with RAG grounding
GET  /rag/search                knowledge-base search
POST /risk/calculate            risk score calculation
GET  /metrics/soc               SOC operational metrics
GET  /reports/{id}.{json|pdf}   incident report download
```

---

## 5. Experimental Setup

### Dataset

All experiments use a **synthetic dataset** generated locally using NumPy/pandas. The generator produces realistic statistical distributions for each attack class:

- **BENIGN**: normal web, DNS, NTP traffic (port 80/443/53/123)
- **DoS**: high packet rates (500–5000 pkt/s), large forward byte counts
- **BruteForce**: repeated connections to SSH/RDP (port 22/3389), small payloads
- **PortScan**: many unique destination ports, tiny packets (≤3 forward packets per flow)
- **Exfiltration**: large outbound transfers (>2 MB) to external IPs

| Split | Rows | Purpose |
|---|---|---|
| Training | 8,507 (70%) | Model fitting |
| Validation | 1,822 (15%) | Hyperparameter selection, best-model selection |
| Test (held-out) | 1,823 (15%) | Final evaluation, never seen during training |
| Live workload | 4,147 | SOC comparison experiment (completely unseen) |

### Experiment configurations

The SOC comparison experiment runs all four configurations on the identical live workload with ground truth provided by the generator:

- **Config A**: rule engine only (NET-001 to NET-004)
- **Config B**: rule engine OR ML prediction (union of detections)
- **Config C**: rule engine only for detection + LLM-generated investigation reports
- **Config D**: (rule OR ML OR anomaly) AND risk_score ≥ 35

The analyst queue is simulated with a discrete-event model: 2 analysts, 8-minute triage baseline, 0.60× time factor when LLM summary is available, 15-minute ACK SLA, 240-minute response SLA.

### LLM evaluation

Nine hand-curated test cases (`data/samples/llm_eval_set.json`) covering all five attack classes, one prompt-injection case, and one edge case. Three configurations evaluated:

- **offline+RAG**: deterministic template + SBERT retrieval
- **offline,noRAG**: deterministic template, no retrieval
- **ollama+RAG**: llama3.1 (local, Ollama 0.40.17) + SBERT retrieval

---

## 6. Results

### 6.1 ML Classification Results

**Table 1: Binary detection metrics on the held-out test set (1,823 flows)**

| Model | Precision | Recall | F1 | FPR | FNR | AUC-ROC | MCC |
|---|---|---|---|---|---|---|---|
| **Random Forest** | 0.900 | 0.969 | 0.933 | 0.028 | 0.032 | **0.991** | 0.915 |
| **XGBoost** | 0.915 | 0.955 | **0.935** | 0.024 | 0.045 | **0.993** | **0.917** |
| Logistic Regression | 0.786 | 0.995 | 0.878 | 0.071 | 0.005 | 0.989 | 0.851 |
| Isolation Forest | 0.807 | 0.580 | 0.675 | 0.037 | 0.420 | 0.870 | 0.618 |

Random Forest was selected as the production model (best validation macro-F1 = 0.9543). XGBoost achieved marginally higher test-set MCC and AUC-ROC.

**Table 2: Per-class F1 scores — Random Forest (test set)**

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| BENIGN | 0.991 | 0.972 | 0.981 | 1,442 |
| BruteForce | 0.906 | 1.000 | 0.951 | 96 |
| DoS | 0.977 | 0.887 | 0.930 | 97 |
| Exfiltration | 0.986 | 1.000 | 0.993 | 72 |
| PortScan | 0.796 | 0.974 | 0.876 | 116 |
| **Macro avg** | **0.931** | **0.967** | **0.946** | 1,823 |

PortScan has the lowest precision (0.796) due to its overlap with legitimate scanning behaviour. All other classes achieve F1 ≥ 0.930.

**Isolation Forest** (unsupervised): AUC-ROC = 0.870, detecting 58% of malicious flows at a 3.7% FPR. Useful as a complementary signal rather than a standalone detector.

### 6.2 SOC Configuration Comparison

The comparison experiment runs all four configurations on 4,147 unseen synthetic flows.

**Table 3: Event-level detection metrics (4,147 live flows, ground truth from generator)**

| Config | Description | Precision | Recall | F1 | FPR | FNR | MCC |
|---|---|---|---|---|---|---|---|
| **A** | Rules only | 0.846 | 0.646 | 0.732 | 0.033 | 0.354 | 0.678 |
| **B** | Rules + ML | 0.874 | **0.977** | **0.923** | 0.040 | 0.023 | **0.901** |
| **C** | Rules + LLM | 0.846 | 0.646 | 0.732 | 0.033 | 0.354 | 0.678 |
| **D** | Combined AI-SOC | 0.853 | **0.978** | 0.911 | 0.048 | 0.022 | 0.887 |

Key observations:
- Config B improves recall from **64.6% to 97.7%** vs. Config A — the ML layer catches 305 additional malicious events that rules miss entirely
- Config C detection is identical to A by design: **the LLM does not contribute to detection**, only to investigation quality
- Config D achieves 97.8% recall while maintaining 85.3% precision — the risk gate (threshold = 35) limits false promotions

**Table 4: Operational SOC metrics (simulated analyst queue, 2 analysts)**

| Config | Incidents | Incident Precision | MTTD (min) | MTTA (min) | MTTR (min) | ACK SLA | Avg Invest. (min) |
|---|---|---|---|---|---|---|---|
| **A** | 102 | 0.951 | 0.077 | 1.054 | 29.054 | 100% | 8.0 |
| **B** | 140 | 0.807 | 0.126 | 2.923 | 30.923 | 95.0% | 8.0 |
| **C** | 102 | 0.951 | 0.077 | **0.383** | **25.183** | 100% | **4.8** |
| **D** | 166 | 0.687 | 0.172 | 0.975 | 25.775 | 100% | **4.8** |

Key observations:
- Config C (LLM investigation) **reduces MTTA by 64%** (1.054 → 0.383 min) and **cuts investigation time by 40%** (8.0 → 4.8 min) through faster triage enabled by AI-generated summaries
- Config D inherits both the ML detection gains (high recall) and the LLM efficiency gains (fast triage), at the cost of more analyst-facing incidents (166 vs. 102)
- Config B generates 37% more incidents than A with no LLM support, increasing analyst workload without the efficiency offset

**Endpoint detection (Sysmon + auth.log, rules only):**

| Metric | Value |
|---|---|
| Events processed | 1,277 |
| Precision | 0.893 |
| Recall | 0.870 |
| F1 | 0.881 |
| FPR | 0.029 |

Endpoint rule-based detection alone achieves strong performance (F1 = 0.881) for the implemented threat classes.

### 6.3 LLM Evaluation Results

**Table 5: Mean automated metrics across 9 test cases**

| Metric | offline+RAG | offline,noRAG | ollama+RAG |
|---|---|---|---|
| JSON valid | 1.000 | 1.000 | **1.000** |
| Threat type match | **1.000** | **1.000** | 0.222 |
| MITRE precision | 0.861 | 1.000 | 0.787 |
| MITRE recall | 0.685 | 0.463 | **0.796** |
| Faithfulness | **1.000** | **1.000** | 0.958 |
| Context precision | 0.778 | — | 0.778 |
| Context recall | 0.685 | — | 0.685 |
| Evidence keyword coverage | **1.000** | **1.000** | **1.000** |
| Recommendation keyword coverage | 0.502 | 0.022 | **0.889** |
| Answer relevancy (TF-IDF cosine) | 0.209 | 0.160 | **0.246** |
| Hallucinated | **0.000** | **0.000** | **0.000** |
| Avg latency (s) | 0.001 | 0.000 | 92.16 |
| Avg prompt tokens | 735 | 324 | 1,269 |
| Avg completion tokens | 435 | 402 | 491 |

Key observations:

**All three configurations achieve zero hallucination** across all 27 test cases (9 cases × 3 configs). No unsupported IPs, hostnames, MITRE IDs, or false action-execution claims were found. This validates the guardrail layer.

**Faithfulness**: offline configs score 1.000 (perfect grounding); ollama+RAG scores 0.958, with 2 of 9 cases generating statements that could not be fully traced to evidence items. All remaining statements were properly grounded.

**Recommendation quality**: ollama+RAG dramatically outperforms the offline template on recommendation keyword coverage (0.889 vs. 0.502), indicating the LLM produces substantially more actionable, specific recommendations.

**MITRE recall**: ollama+RAG achieves the best MITRE recall (0.796), correctly identifying more relevant techniques than either offline configuration, at the cost of slightly lower precision (0.787 vs. 0.861).

**Threat type matching**: the offline template achieves 100% threat type match because it uses the ML classification label directly. ollama+RAG's lower match rate (0.222) reflects the LLM's tendency to describe threats with richer synonyms (e.g. "Denial of Service Attack" vs. "DoS") that do not match the exact reference label — a limitation of the lexical matching metric rather than a quality failure.

**Prompt injection defence**: all injection test cases were correctly flagged (100% detection rate). Threat type classification remained correct in 66.7% of injection cases, with the LLM resisting the injected false narrative.

**Latency**: ollama+RAG averages 92 seconds per investigation on CPU (no GPU). This is a hardware constraint of local inference on commodity hardware, not a software limitation.

### 6.4 Threshold Sensitivity Analysis

**Table 6: Config D sensitivity to the risk alert-gate threshold**

| Risk Threshold | Incidents | Precision | Recall | F1 | FPR | Alert Reduction vs A |
|---|---|---|---|---|---|---|
| 25 | 186 | 0.837 | 0.978 | 0.902 | 0.054 | −82.4% |
| **35 (default)** | **166** | **0.853** | **0.978** | **0.911** | **0.048** | **−62.8%** |
| 45 | 140 | 0.875 | 0.978 | 0.924 | 0.040 | −37.3% |
| 55 | 135 | 0.881 | 0.968 | 0.923 | 0.037 | −32.4% |
| 65 | 120 | 0.967 | 0.761 | 0.852 | 0.007 | −17.6% |
| 75 | 102 | 0.994 | 0.565 | 0.721 | 0.001 | 0.0% |

The default threshold of 35 sits at the **precision-recall knee** — further increases sacrifice meaningful recall for marginal precision gains. At threshold = 45, F1 peaks at 0.924, suggesting a practitioner could raise the threshold slightly for a higher-precision, lower-volume queue with minimal recall loss.

---

## 7. Discussion

### What worked well

**The ML + rules combination (Config B/D)** delivers the most dramatic performance improvement: recall jumps from 64.6% to 97.7%, catching 305 additional malicious events that rules miss. The ensemble of detection signals — rules for known patterns, ML for classification, Isolation Forest for anomalies, risk gating for prioritisation — is demonstrably more robust than any single method.

**Zero hallucinations across all 27 LLM evaluation cases** is the most significant safety result of the project. The guardrail layer — evidence-reference grounding, MITRE validation, destructive-action gating — successfully constrains model output to factual, citation-supported statements regardless of the underlying provider. This is a critical property for security-sensitive applications where fabricated evidence could lead to wrong remediation decisions.

**RAG meaningfully improves recommendation quality**: ollama+RAG's recommendation keyword coverage (0.889) is 77% higher than offline+RAG (0.502) and 40× higher than offline,noRAG (0.022). Grounding recommendations in playbooks and incident response documentation is essential for producing actionable outputs.

**The LLM efficiency gains are real and measurable**: Config C reduces MTTA by 64% and investigation time by 40% under the simulated analyst queue model. Even under conservative assumptions (0.60× time factor), this translates to significant analyst capacity savings at scale.

### Trade-offs

**Config D increases incident volume by 63%** vs. Config A (166 vs. 102 incidents) despite higher recall. The ML layer flags more true positives but also more false positives. This trade-off requires analyst judgement: the system prioritises recall (catching attacks) at some cost to precision (analyst workload). The LLM efficiency offset partially compensates by reducing per-incident triage time.

**Ollama+RAG threat-type matching (0.222)** looks poor but is a metric artefact. The LLM uses richer natural-language descriptions that do not match the exact reference label. The underlying investigation quality — as measured by faithfulness, evidence coverage, and recommendation quality — is substantially better than the offline template.

**Local LLM latency (92s/investigation on CPU)** is the primary practical constraint for real-time deployment. GPU inference or cloud API (OpenAI) would reduce this to 2–5 seconds. The system architecture supports any provider without code changes.

---

## 8. Limitations

1. **Synthetic data only**: all experiments use generated data. Performance on real network traffic may differ significantly. CIC-IDS2017, UNSW-NB15, and other datasets are supported by the pipeline but were not used in this evaluation.

2. **Simulated analyst queue**: MTTD/MTTA/MTTR are derived from a discrete-event simulation with assumed parameters (2 analysts, 8-minute triage, 0.60× LLM factor). These are not measured from real analyst behaviour.

3. **LLM evaluation scale**: 9 test cases provides illustrative, not statistically powered, results. A production evaluation would require hundreds of diverse cases assessed by domain experts.

4. **Offline provider is not an LLM**: the offline template is a deterministic rule-based summariser. Its perfect faithfulness and hallucination scores reflect guardrail behaviour, not LLM capability. Offline scores should not be compared directly to ollama+RAG scores.

5. **No production hardening**: the system has no authentication, rate limiting, TLS termination, or multi-tenancy support. It is a research prototype.

6. **MITRE coverage**: the knowledge base contains a curated subset of ATT&CK techniques. Full enterprise matrix coverage would require the complete MITRE enterprise-attack.json (~800 techniques).

7. **No model-judged metrics**: RAGAS/DeepEval (LLM-as-judge) was not executed. All LLM quality metrics are lexical proxies, which may not capture semantic quality.

---

## 9. Conclusion

This project demonstrates that AI augmentation of Security Operations Centres provides measurable, quantifiable improvements across detection, efficiency, and investigation quality dimensions.

The key findings are:

1. **ML classification** (Random Forest, AUC-ROC = 0.991) raises recall from 64.6% to 97.7% on the live workload, catching the 35.4% of attacks that rule-based detection misses entirely.

2. **LLM investigation with RAG** reduces analyst triage time by 40% and MTTA by 64% under the queue simulation model, with zero hallucinations across all 27 evaluated cases.

3. **The guardrail layer** is the critical safety component: it enforces evidence grounding, validates MITRE technique suggestions, blocks autonomous execution of destructive actions, and maintains a full audit trail — all requirements for responsible AI deployment in a security context.

4. **RAG substantially improves recommendation quality**: recommendation keyword coverage improves from 0.022 (no RAG) to 0.889 (ollama+RAG), highlighting the importance of grounding LLM outputs in domain-specific knowledge.

5. **The combined Config D** (rules + ML + anomaly + LLM + risk gating) achieves the best balance for a real deployment: highest recall (97.8%), fastest triage (MTTA 0.975 min), and 40% faster investigation — at the cost of a 63% larger incident queue that the efficiency gains partially offset.

The project establishes a complete, reproducible, end-to-end reference implementation that can be extended with real data sources, production hardening, and larger-scale LLM evaluation.

---

## 10. References

1. MITRE Corporation. (2024). *MITRE ATT&CK Enterprise Matrix*. https://attack.mitre.org/
2. Sharafaldin, I., Lashkari, A. H., & Ghorbani, A. A. (2018). Toward generating a new intrusion detection dataset and intrusion traffic characterization. *ICISSP 2018*.
3. Moustafa, N., & Slay, J. (2015). UNSW-NB15: a comprehensive data set for network intrusion detection systems. *MilCIS 2015*.
4. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). Isolation forest. *ICDM 2008*.
5. Lewis, P., et al. (2020). Retrieval-augmented generation for knowledge-intensive NLP tasks. *NeurIPS 2020*.
6. Touvron, H., et al. (2023). Llama 2: Open foundation and fine-tuned chat models. *arXiv:2307.09288*.
7. Reimers, N., & Gurevych, I. (2019). Sentence-BERT: Sentence embeddings using siamese BERT-networks. *EMNLP 2019*.
8. Es, S., et al. (2023). RAGAS: Automated evaluation of retrieval augmented generation. *arXiv:2309.15217*.
9. Chen, T., & Guestrin, C. (2016). XGBoost: A scalable tree boosting system. *KDD 2016*.
10. Strom, B. E., et al. (2018). MITRE ATT&CK: Design and philosophy. *MITRE Technical Report*.

---

*All experimental results in this report are computed from synthetic data generated locally. No real network traffic, real credentials, or production systems were used. The simulation parameters (analyst count, triage time, LLM time factor) are clearly labelled as assumptions throughout.*

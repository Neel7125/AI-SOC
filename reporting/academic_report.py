"""Academic experiment report (Markdown + PDF) assembled ONLY from measured result files."""
from __future__ import annotations

import json

import pandas as pd
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer

import config


def _load(p):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def build_academic_report() -> dict:
    ml = _load(config.ML_EVAL_DIR / "evaluation_metrics.json")
    llm = _load(config.LLM_EVAL_DIR / "evaluation_summary.json")
    cmp_ = _load(config.SOC_CMP_DIR / "comparison_summary.json")
    eda = _load(config.PROCESSED_DIR / f"eda_{config.ACTIVE_DATASET}.json")
    reg = _load(config.MODELS_DIR / "registry.json")
    if not ml:
        raise FileNotFoundError("Run scripts/train_all.py and scripts/evaluate_all.py first")
    md = ["# AI-Driven SOC - Experiment Report", "",
          "> All numbers below are read from files produced by the experiment scripts. Unless a real dataset path is configured, the data is **synthetic**; "
          "results must not be presented as real-world findings.", "", "## 1. Dataset description"]
    if eda:
        md += [f"Dataset `{eda['dataset']}`: {eda['rows']} rows, {eda['columns']} columns. Class counts: {eda['class_counts']}. "
               f"Imbalance ratio (majority/minority): {eda['imbalance_ratio_majority_to_minority']}."]
    md += ["", "## 2. Experimental setup", "Stratified 70/15/15 split (seed 42); preprocessing (imputation medians, feature selection, encoding) fitted on the training split only; "
           "model selection on validation macro-F1; all reported metrics from the held-out test split. SOC comparison uses a separate unseen workload (different generator seed).",
           "", "## 3. Algorithms"]
    for n, m in (reg or {}).get("models", {}).items():
        md.append(f"- **{n}**: {m.get('hyperparameters')} (train rows {m.get('train_rows', 'benign only')}, {m.get('train_seconds', '-')}s)")
    md += ["", "## 4. Evaluation metrics (test set, binary: malicious vs benign)", "", "| Model | Precision | Recall | F1 | FPR | FNR | MCC | AUC-ROC | AUC-PR |", "|---|---|---|---|---|---|---|---|---|"]
    for n, v in ml["metrics"].items():
        b = v["binary"]
        md.append(f"| {n} | {b['precision']} | {b['recall']} | {b['f1']} | {b['false_positive_rate']} | {b['false_negative_rate']} | {b['mcc']} | {b.get('auc_roc')} | {b.get('auc_pr')} |")
    md += ["", f"Best model by validation macro-F1: **{ml['best_model']}**.", "", "## 5. Confusion matrices, ROC and PR curves"]
    for f in ("confusion_matrix", "normalized_confusion_matrix", "multiclass_confusion_matrix", "roc_curve", "precision_recall_curve", "feature_importance", "model_comparison", "anomaly_scores"):
        md.append(f"![{f}](../ml_evaluation/{f}.png)")
    md += ["", "## 6. LLM evaluation"]
    if llm:
        md += [f"Cases: {llm['cases']}; configurations: {llm['configs']}; not run: {llm['providers_not_run']}.", "", "```json", json.dumps(llm["per_config_means"], indent=1), "```",
               "Caveats: " + " | ".join(llm["caveats"]), "", "![latency](../llm_evaluation/latency_comparison.png)"]
    md += ["", "## 7. Traditional vs AI SOC comparison"]
    if cmp_:
        df = pd.DataFrame(cmp_["table"])[["config", "name", "precision", "recall", "f1", "false_positive_rate", "false_negative_rate", "incidents", "MTTD_min", "MTTA_min", "MTTR_min", "alert_reduction_vs_A"]]
        md += [df.to_markdown(index=False) if hasattr(df, "to_markdown") else df.to_string(index=False), "",
               f"Endpoint rules (no ML): {cmp_['endpoint_rules_only']}", "", f"LLM detection credit: {cmp_['llm_detection_credit']}", "",
               "Assumptions: " + json.dumps(cmp_["assumptions"]), "", "![detection](../soc_comparison/detection_comparison.png)", "![ops](../soc_comparison/operational_comparison.png)"]
    md += ["", "## 8. Limitations",
           "- Synthetic data with generator-defined overlap; real-dataset performance will differ (CIC-IDS2017 etc. are supported via dataset config but not bundled).",
           "- Flows from the same attack burst can appear in both train and test splits (flow-level, not burst-level split) - optimistic bias.",
           "- Analyst-queue timings (MTTA/MTTR/investigation time) are simulated from assumed parameters, not measured with humans.",
           "- Offline LLM provider is a template; LLM metrics reflect guardrail/pipeline behaviour unless OpenAI/Ollama was configured.",
           "- RAG uses TF-IDF by default; semantic embeddings (sentence-transformers) are optional.",
           "- Rule-based detection thresholds are illustrative.", "", "## 9. Conclusion",
           "The measured results show whether ML and anomaly detection add recall beyond fixed rules and what that costs in alert volume; "
           "see the tables above for the actual figures. LLM components were evaluated for grounding, validity and cost, not credited with detection."]
    text = "\n".join(md)
    mdp = config.REPORTS_DIR / "academic_report.md"
    mdp.write_text(text, encoding="utf-8")
    # PDF
    ss = getSampleStyleSheet(); el = []
    for line in text.split("\n"):
        if line.startswith("!["):
            p = (config.REPORTS_DIR / line[line.index("(") + 1:-1]).resolve()
            if p.exists():
                el.append(Image(str(p), width=11 * cm, height=8 * cm, kind="proportional"))
        elif line.startswith("# "):
            el.append(Paragraph(line[2:], ss["Title"]))
        elif line.startswith("## "):
            el.append(Paragraph(line[3:], ss["Heading2"]))
        elif line.strip() and not line.startswith(("```", "|---")):
            el.append(Paragraph(line.replace("&", "&amp;").replace("<", "&lt;").replace("|", " | ")[:1500], ss["BodyText"]))
        else:
            el.append(Spacer(1, 4))
    pdfp = config.REPORTS_DIR / "academic_report.pdf"
    SimpleDocTemplate(str(pdfp), pagesize=A4).build(el)
    return {"markdown": str(mdp), "pdf": str(pdfp)}

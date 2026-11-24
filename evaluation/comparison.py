"""Traditional SOC vs AI SOC experiment (A: rules, B: +ML, C: +LLM investigation, D: combined).

Same workload (unseen live flow set), same ground truth, same analyst-queue assumptions for every configuration.
LLM role: configuration C detects exactly what A detects - the LLM is credited ONLY with investigation effects
(assumed time factor) and its measured latency/token/cost, never with detection gains.
"""
from __future__ import annotations

import json
import logging

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

import config
from detection.alert_processor import group_incidents, score_endpoint, score_flows, to_alert_rows
from evaluation.classification_metrics import binary_metrics
from evaluation.soc_metrics import simulate_queue, soc_metrics
from ingestion.csv_loader import load_flow_events
from ingestion.linux_parser import parse_auth_log
from ingestion.sysmon_parser import parse_sysmon
from llm_engine.investigation import investigate
from ml_engine.predict import Predictor

log = logging.getLogger(__name__)
CONFIGS = {"A": "Traditional SOC (rules)", "B": "ML SOC (rules + ML)", "C": "LLM SOC (rules + LLM investigation)",
           "D": "Combined AI SOC (rules + ML + anomaly + LLM + risk)"}


def _llm_cost(groups: pd.DataFrame, rows: list[dict], n: int, provider: str | None) -> dict:
    if not rows:
        return {}
    step = max(1, len(rows) // n)
    lat, pt, ct, cost, ok, est = [], [], [], [], 0, False
    for i in list(range(0, len(rows), step))[:n]:
        rec = investigate(alert=rows[i], event={"description": groups["description"].iloc[i], "command_line": None}, related=[],
                          provider=provider, save=False)
        lat.append(rec["latency_s"]); pt.append(rec["prompt_tokens"]); ct.append(rec["completion_tokens"]); cost.append(rec["cost_usd"])
        ok += int(rec["valid_json"]); est = est or rec["tokens_estimated"]; model = rec["model"]
    k = len(lat)
    return {"llm_model": model, "llm_sampled_incidents": k, "llm_valid_json_rate": round(ok / k, 3),
            "llm_latency_mean_s": round(sum(lat) / k, 4), "llm_tokens_per_incident": round((sum(pt) + sum(ct)) / k, 1),
            "llm_cost_per_incident_usd": round(sum(cost) / k, 6), "llm_projected_total_cost_usd": round(sum(cost) / k * len(rows), 4),
            "llm_projected_total_tokens": int((sum(pt) + sum(ct)) / k * len(rows)), "tokens_estimated": est}


def run_comparison(n_llm: int = 25, provider: str | None = None) -> dict:
    out = config.SOC_CMP_DIR
    live = load_flow_events(config.SYNTH_DIR / "live_flows.csv")
    scored = score_flows(live, Predictor())
    gt = scored["gt_label"].astype(int)
    sim = config.SOC_SIM
    table, cat_recall = [], {}
    for k, name in CONFIGS.items():
        mask = scored[f"alert_{k}"].astype(bool)
        m = binary_metrics(gt, mask.astype(int))
        groups = group_incidents(scored, mask, ["src_ip"], f"det_time_{k}")
        pri = groups["risk_score"] if k == "D" else None                     # only D has risk-based prioritisation
        factor = sim["llm_time_factor"] if k in ("C", "D") else 1.0
        q = simulate_queue(groups["group_detect_time"], pri, time_factor=factor)
        al = pd.DataFrame({"created_at": groups["first_event_time"], "detected_at": groups["group_detect_time"], "acknowledged_at": q["acknowledged_at"],
                           "responded_at": q["responded_at"], "gt_label": groups["group_gt"]})
        sm = soc_metrics(al)
        row = {"config": k, "name": name, "events_flagged": int(mask.sum()), **{x: m[x] for x in ("precision", "recall", "f1", "false_positive_rate", "false_negative_rate", "mcc", "tp", "fp", "fn", "tn")},
               "incidents": sm["alert_volume"], "incident_precision": sm["alert_precision"], "MTTD_min": sm["MTTD_min"], "MTTA_min": sm["MTTA_min"],
               "MTTR_min": sm["MTTR_min"], "sla_ack_compliance": sm["sla_ack_compliance"], "avg_investigation_min": sm["avg_investigation_minutes"]}
        if k in ("C", "D"):
            rows = to_alert_rows(groups, "comparison", with_ml=True)
            row.update(_llm_cost(groups, rows, n_llm, provider))
        table.append(row)
        cat_recall[k] = scored[gt == 1].assign(hit=mask[gt == 1]).groupby("gt_category")["hit"].mean().round(4)
    df = pd.DataFrame(table)
    base = df.loc[df.config == "A", "incidents"].iloc[0]
    df["alert_reduction_vs_A"] = ((base - df["incidents"]) / base).round(4)
    df.to_csv(out / "comparison_table.csv", index=False)
    pd.DataFrame(cat_recall).to_csv(out / "category_recall.csv")
    # Transparency: sensitivity of config D to its alert-gate threshold (no threshold is tuned on this workload)
    sweep = []
    for t in (25, 35, 45, 55, 65, 75):
        mk = scored["category"].notna() & (scored["risk_score"] >= t)
        mm = binary_metrics(gt, mk.astype(int))
        gr = group_incidents(scored, mk, ["src_ip"], "det_time_D")
        sweep.append({"risk_threshold": t, "incidents": len(gr), "precision": mm["precision"], "recall": mm["recall"], "f1": mm["f1"],
                      "false_positive_rate": mm["false_positive_rate"], "alert_reduction_vs_A": round((base - len(gr)) / base, 4)})
    pd.DataFrame(sweep).to_csv(out / "threshold_sweep.csv", index=False)

    ax = df.set_index("config")[["precision", "recall", "f1"]].plot(kind="bar", figsize=(7, 4.2), rot=0)
    ax.set_ylim(0, 1.05); ax.set_title("Event-level detection: A rules | B +ML | C +LLM | D combined"); plt.tight_layout(); plt.savefig(out / "detection_comparison.png", dpi=130); plt.close()
    fig, axs = plt.subplots(1, 3, figsize=(12, 3.8))
    df.set_index("config")["incidents"].plot(kind="bar", ax=axs[0], rot=0, color="#e76f51", title="Analyst-facing incidents")
    df.set_index("config")[["MTTA_min", "MTTR_min"]].plot(kind="bar", ax=axs[1], rot=0, title="MTTA / MTTR (min, simulated queue)")
    df.set_index("config")[["false_positive_rate", "false_negative_rate"]].plot(kind="bar", ax=axs[2], rot=0, title="FPR / FNR (event level)")
    plt.tight_layout(); fig.savefig(out / "operational_comparison.png", dpi=130); plt.close(fig)
    pd.DataFrame(cat_recall).plot(kind="bar", figsize=(8, 4), rot=20, title="Recall by attack category and configuration"); plt.tight_layout()
    plt.savefig(out / "category_recall.png", dpi=130); plt.close()

    ep = pd.concat([parse_sysmon(config.SYNTH_DIR / "sysmon_events.jsonl"), parse_auth_log(config.SYNTH_DIR / "auth.log", config.SYNTH_DIR / "auth_log_truth.csv")], ignore_index=True)
    eps = score_endpoint(ep)
    em = binary_metrics(eps["gt_label"].astype(int), eps["rule_hit"].astype(int))
    payload = {"workload": f"{len(live)} unseen SYNTHETIC flows (seed 2024), ground truth from generator", "table": json.loads(df.to_json(orient="records")),
               "endpoint_rules_only": {"events": len(ep), **{x: em[x] for x in ("precision", "recall", "f1", "false_positive_rate", "false_negative_rate")}},
               "assumptions": {**sim, "ml_inference_delay_s": 0.5, "note": "MTTD/MTTA/MTTR and investigation time come from a SIMULATED analyst queue with these assumed parameters; "
                               "detection metrics are measured from actual predictions; LLM latency/tokens are measured (offline template provider unless configured)."},
               "llm_detection_credit": "None. Config C detection == config A by design; the LLM is not part of the detection decision."}
    (out / "comparison_summary.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload

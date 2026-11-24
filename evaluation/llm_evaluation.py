"""LLM evaluation (separate from ML classification evaluation).

Metric taxonomy (also written to evaluation_summary.json):
  AUTOMATED  : JSON validity, latency, tokens, cost estimate, threat-type match, MITRE precision/recall, retrieval precision/recall,
               faithfulness (evidence-reference grounding, lexical), hallucination heuristics (unknown IPs/hosts, invalid MITRE IDs,
               false 'action executed' claims), keyword coverage, answer relevancy (TF-IDF cosine vs reference).
  MODEL-JUDGED: none computed. RAGAS / DeepEval (LLM-as-judge) were NOT run; the automated metrics above are lexical proxies for them.
  MANUAL     : the curated reference set (data/samples/llm_eval_set.json) was written by hand by the project author.
"""
from __future__ import annotations

import json
import logging
import re

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

import config
from llm_engine.investigation import investigate
from llm_engine.llm_provider import Provider

log = logging.getLogger(__name__)
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
HOST = re.compile(r"\b(?:ws|srv)-[a-z]+-\d\d\b|\b[a-z]+-\d\d\b", re.I)
EXEC_CLAIM = re.compile(r"(has|have|was|were) (been )?(isolated|blocked|disabled|quarantined|terminated)|i (isolated|blocked|disabled)", re.I)
REF = re.compile(r"^\[(E\d+)\]\s*(.*)$", re.S)
TOK = re.compile(r"[a-z0-9_.\-]+")


def _toks(s: str) -> set[str]:
    return set(TOK.findall(str(s).lower()))


def faithfulness(resp: dict, E: dict[str, str]) -> tuple[float, int, int]:
    stmts = list(resp.get("evidence", [])) + list(resp.get("confirmed_facts", []))
    if not stmts:
        return 0.0, 0, 0
    ok = 0
    for s in stmts:
        m = REF.match(str(s))
        if not m or m.group(1) not in E:
            continue
        t = _toks(m.group(2)); ev = _toks(E[m.group(1)])
        if t and len(t & ev) / len(t) >= 0.7:
            ok += 1
    return ok / len(stmts), ok, len(stmts)


def hallucination(resp: dict, ctx: dict, warnings: list[str]) -> dict:
    text = json.dumps(resp)
    ctx_text = json.dumps(ctx, default=str).lower()
    bad_ip = [i for i in set(IP.findall(text)) if i not in ctx_text]
    bad_host = [h for h in set(HOST.findall(text)) if h.lower() not in ctx_text and not re.match(r"t\d", h.lower())]
    bad_mitre = sum(1 for w in warnings if "rejected" in w and "MITRE" in w)
    exec_claims = len(EXEC_CLAIM.findall(text))
    n = len(bad_ip) + len(bad_host) + bad_mitre + exec_claims
    return {"unsupported_ips": len(bad_ip), "unsupported_hosts": len(bad_host), "invalid_mitre_ids": bad_mitre, "false_action_claims": exec_claims,
            "hallucination_flags": n, "hallucinated": int(n > 0)}


def retrieval_scores(retr: list[dict], exp: dict) -> tuple[float, float]:
    if not retr:
        return float("nan"), float("nan")
    want = [exp["playbook"].lower()] + [t.lower() for t in exp["mitre"]]
    rel = lambda r: any(w in r["title"].lower() for w in want)
    prec = sum(rel(r) for r in retr) / len(retr)
    found = sum(any(w in r["title"].lower() for r in retr) for w in want)
    return prec, found / len(want)


def run_llm_evaluation(configs: list[tuple[str, str, bool]] | None = None) -> dict:
    out = config.LLM_EVAL_DIR
    cases = json.loads((config.SAMPLES_DIR / "llm_eval_set.json").read_text(encoding="utf-8"))
    configs = configs or [("offline+RAG", "offline", True), ("offline,noRAG", "offline", False)]
    for name, prov in (("openai+RAG", "openai"), ("ollama+RAG", "ollama")):
        if Provider(prov).available()[0] and not any(c[1] == prov for c in configs):
            configs.append((name, prov, True))
    skipped = [n for n, p in (("openai", "openai"), ("ollama", "ollama")) if not any(c[1] == p for c in configs)]
    rows, texts, refs = [], [], []
    for label, prov, rag in configs:
        for c in cases:
            rec = investigate(alert=dict(c["alert"]), event=c["event"], related=[], provider=prov, use_rag=rag, save=False)
            resp, exp = rec["response"], c["expected"]
            faith, ok, tot = faithfulness(resp, rec["evidence_items"])
            hall = hallucination(resp, rec["context"], rec["warnings"])
            cp, cr = retrieval_scores(rec["retrieval_text"] if "retrieval_text" in rec else rec["retrieved_text"], exp)
            got = set(resp.get("mitre_techniques", [])); want = set(exp["mitre"])
            body = " ".join(resp.get("investigation_steps", []) + resp.get("recommended_actions", [])).lower()
            ev_body = (resp.get("incident_summary", "") + " " + " ".join(resp.get("evidence", []))).lower()
            ans = resp.get("incident_summary", "") + " " + " ".join(resp.get("investigation_steps", []) + resp.get("recommended_actions", []))
            texts.append(ans); refs.append(exp["reference"])
            rows.append({"config": label, "case": c["id"], "note": c["note"], "provider": rec["provider"], "model": rec["model"], "rag_used": rec["rag_used"],
                         "json_valid": int(rec["valid_json"]), "threat_type_match": int(resp.get("threat_type", "").lower() == exp["threat_type"].lower()),
                         "mitre_precision": round(len(got & want) / len(got), 3) if got else 0.0, "mitre_recall": round(len(got & want) / len(want), 3),
                         "faithfulness": round(faith, 3), "grounded_statements": ok, "total_statements": tot,
                         "context_precision": cp, "context_recall": cr,
                         "evidence_keyword_coverage": round(sum(k.lower() in ev_body for k in exp["evidence_keywords"]) / len(exp["evidence_keywords"]), 3),
                         "recommendation_keyword_coverage": round(sum(k.lower() in body for k in exp["recommendation_keywords"]) / len(exp["recommendation_keywords"]), 3),
                         **hall, "injection_case": int(bool(exp.get("injection"))),
                         "injection_flagged": int(any("injection" in w for w in rec["warnings"])),
                         "latency_s": rec["latency_s"], "prompt_tokens": rec["prompt_tokens"], "completion_tokens": rec["completion_tokens"],
                         "tokens_estimated": rec["tokens_estimated"], "cost_usd": rec["cost_usd"]})
    df = pd.DataFrame(rows)
    vec = TfidfVectorizer(stop_words="english").fit(texts + refs)
    sims = [float(cosine_similarity(vec.transform([a]), vec.transform([r]))[0, 0]) for a, r in zip(texts, refs)]
    df["answer_relevancy"] = np.round(sims, 3)
    df.to_csv(out / "llm_evaluation.csv", index=False)
    df[["config", "case", "faithfulness", "grounded_statements", "total_statements"]].to_csv(out / "faithfulness_results.csv", index=False)
    df[["config", "case", "unsupported_ips", "unsupported_hosts", "invalid_mitre_ids", "false_action_claims", "hallucination_flags", "hallucinated"]].to_csv(out / "hallucination_analysis.csv", index=False)
    df[["config", "case", "provider", "model", "prompt_tokens", "completion_tokens", "tokens_estimated", "cost_usd"]].to_csv(out / "token_usage.csv", index=False)
    lat = df.groupby("config")["latency_s"].mean()
    ax = lat.plot(kind="bar", figsize=(6, 4), rot=0, color="#264653"); ax.set_ylabel("Mean latency per investigation (s)")
    ax.set_title("LLM response latency by configuration"); plt.tight_layout(); plt.savefig(out / "latency_comparison.png", dpi=130); plt.close()
    num = ["json_valid", "threat_type_match", "mitre_precision", "mitre_recall", "faithfulness", "context_precision", "context_recall",
           "evidence_keyword_coverage", "recommendation_keyword_coverage", "answer_relevancy", "hallucinated", "latency_s", "prompt_tokens", "completion_tokens", "cost_usd"]
    summary = {"cases": len(cases), "configs": [c[0] for c in configs], "providers_not_run": skipped,
               "per_config_means": json.loads(df.groupby("config")[num].mean().round(4).to_json(orient="index")),
               "injection_cases": {"flagged_rate": float(df[df.injection_case == 1].injection_flagged.mean()),
                                   "threat_type_still_correct": float(df[df.injection_case == 1].threat_type_match.mean())},
               "metric_types": {"automated": ["json_valid", "latency_s", "tokens", "cost", "threat_type_match", "mitre_precision/recall", "context_precision/recall",
                                              "faithfulness (lexical grounding)", "hallucination heuristics", "answer_relevancy (tf-idf cosine)"],
                                "model_judged": "none run (RAGAS/DeepEval not executed)", "manual": "reference dataset curated by author"},
               "caveats": ["offline provider is a deterministic template, not an LLM: its scores show pipeline/guardrail behaviour, not LLM capability",
                           "tokens for offline provider are estimated as chars/4", "9 curated cases: results are illustrative, not statistically powered"]}
    (out / "evaluation_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary

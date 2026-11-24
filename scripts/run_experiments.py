"""Run LLM + SOC comparison experiments. Usage: python scripts/run_experiments.py [--provider offline|openai|ollama]"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from evaluation.comparison import run_comparison  # noqa: E402
from evaluation.llm_evaluation import run_llm_evaluation  # noqa: E402
from rag.retriever import build_index  # noqa: E402

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--provider", default=None); a = ap.parse_args()
    build_index()
    print("LLM evaluation:", json.dumps(run_llm_evaluation()["per_config_means"], indent=1))
    c = run_comparison(provider=a.provider)
    for r in c["table"]:
        print({k: r.get(k) for k in ("config", "precision", "recall", "f1", "false_positive_rate", "incidents", "MTTA_min", "MTTR_min", "alert_reduction_vs_A")})

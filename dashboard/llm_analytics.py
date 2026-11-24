from __future__ import annotations

import pandas as pd
import streamlit as st

import config
from dashboard import common as C


def render() -> None:
    st.title("LLM Evaluation")
    st.caption("Evaluated separately from the ML classifiers. Metric types: AUTOMATED (lexical/structural proxies), MODEL-JUDGED (none run - RAGAS/DeepEval not executed), MANUAL (hand-curated reference set).")
    s = C.read_json(config.LLM_EVAL_DIR / "evaluation_summary.json")
    if not s:
        st.info("Run `python scripts/run_experiments.py` or use System Configuration -> setup.")
        return
    if "offline" in " ".join(s["configs"]):
        st.markdown("<div class='warnbox'>The <b>offline</b> provider is a deterministic template, not an LLM: its scores validate the pipeline and guardrails, not LLM capability. Configure OpenAI/Ollama and re-run to evaluate real models.</div>", unsafe_allow_html=True)
    st.dataframe(pd.DataFrame(s["per_config_means"]).T, use_container_width=True)
    st.write("Injection test cases:", s["injection_cases"])
    st.write({"providers not run": s["providers_not_run"], "caveats": s["caveats"]})
    t = st.tabs(["Per-case results", "Faithfulness", "Hallucination", "Tokens & cost", "Latency"])
    p = config.LLM_EVAL_DIR
    t[0].dataframe(pd.read_csv(p / "llm_evaluation.csv"), hide_index=True, use_container_width=True)
    t[1].dataframe(pd.read_csv(p / "faithfulness_results.csv"), hide_index=True, use_container_width=True)
    t[2].dataframe(pd.read_csv(p / "hallucination_analysis.csv"), hide_index=True, use_container_width=True)
    t[3].dataframe(pd.read_csv(p / "token_usage.csv"), hide_index=True, use_container_width=True)
    with t[4]:
        C.show_image(p / "latency_comparison.png")
    if st.button("Re-run LLM evaluation"):
        from evaluation.llm_evaluation import run_llm_evaluation
        with st.spinner("Running..."):
            run_llm_evaluation()
        st.rerun()

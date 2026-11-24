from __future__ import annotations

from pathlib import Path

import pandas as pd
import streamlit as st

import config
from dashboard import common as C
from llm_engine.llm_provider import Provider
from siem.splunk_client import SplunkClient, list_queries


def render() -> None:
    st.title("System Configuration")
    st.subheader("Setup")
    ok, miss = C.ready()
    st.write("Status:", "ready" if ok else f"missing: {', '.join(miss)}")
    c1, c2 = st.columns(2)
    if c1.button("Run full setup (generate -> train -> evaluate -> pipeline -> experiments)", type="primary"):
        box = st.empty(); log = []
        from scripts.setup_demo import run_full_setup
        with st.spinner("This takes about a minute..."):
            run_full_setup(lambda m: (log.append(str(m)), box.code("\n".join(log))))
        st.cache_resource.clear(); st.success("Setup complete")
    if c2.button("Retrain models only (explicit)"):
        from ml_engine.train import train_all
        with st.spinner("Training..."):
            st.json(train_all())
        st.cache_resource.clear()
    st.subheader("LLM providers")
    for p in ("offline", "openai", "ollama"):
        a, why = Provider(p).available()
        st.write(f"- **{p}**: {'available' if a else 'unavailable'} ({why})")
    st.write({"active provider (LLM_PROVIDER)": config.LLM_PROVIDER, "openai model": config.OPENAI_MODEL, "ollama model": config.OLLAMA_MODEL,
              "embedding backend": config.EMBEDDING_BACKEND, "RAG top-k": config.RAG_TOP_K, "API key set": bool(config.OPENAI_API_KEY)})
    st.caption("Secrets are read from .env only and are never displayed.")
    st.subheader("Datasets (paths configurable in .env; nothing auto-downloaded)")
    st.dataframe(pd.DataFrame([{"dataset": k, "type": v["type"], "path": v["path"], "found": Path(v["path"]).exists()} for k, v in config.DATASETS.items()]), hide_index=True, use_container_width=True)
    st.write("Active dataset:", config.ACTIVE_DATASET)
    st.subheader("Splunk / SIEM")
    cli = SplunkClient()
    st.write({"configured": cli.configured(), "reachable": cli.available() if cli.configured() else False,
              "mode": "Splunk" if cli.configured() else "local CSV/JSON ingestion (Splunk not configured)"})
    q = list_queries()
    sel = st.selectbox("SPL detection query", list(q))
    st.code(q[sel], language="sql")
    st.subheader("Risk & SOC parameters")
    st.json({"risk_weights": config.RISK_WEIGHTS, "risk_levels": config.RISK_LEVELS, "alert_risk_threshold": config.ALERT_RISK_THRESHOLD,
             "ml_threshold": config.ML_THRESHOLD, "soc_simulation_assumptions": config.SOC_SIM})
    st.subheader("System audit log (latest 100)")
    from database import repository as repo
    st.dataframe(repo.get_audit().head(100), hide_index=True, use_container_width=True)

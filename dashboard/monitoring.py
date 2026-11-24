from __future__ import annotations

import time

import plotly.express as px
import streamlit as st

from dashboard import common as C
from database import repository as repo
from detection.pipeline import stream_batch


def render() -> None:
    st.title("Live Security Monitoring")
    C.synthetic_banner()
    if not C.guard():
        return
    st.caption("Near-real-time replay: each click processes the next batch of held-back synthetic flows through rules -> ML -> anomaly -> risk -> incidents.")
    c1, c2, c3 = st.columns([1, 1, 2])
    n = c1.number_input("Flows per batch", 50, 1000, 300, 50)
    auto = c3.checkbox("Auto-stream (every 3 s until exhausted)")
    if c2.button("Ingest next batch", type="primary") or auto:
        with st.spinner("Processing batch..."):
            res = stream_batch(int(n))
        st.session_state["last_stream"] = res
        if auto and res.get("status") == "ok":
            time.sleep(3)
            st.rerun()
    last = st.session_state.get("last_stream")
    if last:
        st.json(last)
    df = repo.query_df("SELECT * FROM alerts WHERE workload='stream' ORDER BY created_at DESC")
    if df.empty:
        st.info("No streamed incidents yet - ingest a batch.")
        return
    m = st.columns(3)
    m[0].metric("Streamed incidents", len(df)); m[1].metric("Critical/High", int(df.risk_level.isin(["Critical", "High"]).sum()))
    m[2].metric("Max risk", f"{df.risk_score.max():.1f}")
    st.plotly_chart(px.scatter(df, x="created_at", y="risk_score", color="risk_level", color_discrete_map=C.RISK_COLORS, hover_data=["title", "attack_category"],
                               title="Streamed incidents by time and risk"), use_container_width=True)
    st.dataframe(df[["alert_id", "created_at", "title", "attack_category", "risk_score", "risk_level", "ml_prediction", "anomaly_score", "event_count"]], use_container_width=True, hide_index=True)

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

import config
from dashboard import common as C
from evaluation.soc_metrics import soc_metrics


def render_perf() -> None:
    st.title("SOC Performance Analytics")
    if not C.guard():
        return
    df = C.sidebar_filters(C.alerts_df())
    m = soc_metrics(df)
    st.markdown("<div class='warnbox'>MTTD/MTTA/MTTR use timestamps from the <b>simulated</b> analyst queue (assumed parameters) unless an analyst changed status in the dashboard (recorded). Rows with missing timestamps are excluded.</div>", unsafe_allow_html=True)
    a = st.columns(4)
    a[0].metric("Alert (incident) volume", m["alert_volume"]); a[1].metric("MTTD (min)", m.get("MTTD_min")); a[2].metric("MTTA (min)", m.get("MTTA_min")); a[3].metric("MTTR (min)", m.get("MTTR_min"))
    b = st.columns(4)
    b[0].metric("ACK SLA compliance", m.get("sla_ack_compliance")); b[1].metric("Response SLA compliance", m.get("sla_response_compliance"))
    b[2].metric("Avg investigation (min)", m.get("avg_investigation_minutes")); b[3].metric("Alert precision", m.get("alert_precision"))
    from database import repository as repo
    inv = repo.get_investigations()
    st.metric("Avg LLM response time (s)", round(inv.latency_s.mean(), 4) if len(inv) else "no investigations yet")
    st.json({k: m[k] for k in ("sla_ack_compliance", "sla_response_compliance", "alerts_true_positive", "alerts_false_positive")})
    d = df.dropna(subset=["detected_at", "acknowledged_at"]).copy()
    if len(d):
        d["ack_minutes"] = (d.acknowledged_at - d.detected_at).dt.total_seconds() / 60
        st.plotly_chart(px.histogram(d, x="ack_minutes", nbins=30, title="Time to acknowledge (min)"), use_container_width=True)
    st.write("SLA targets (config):", {k: v for k, v in config.SOC_SIM.items() if "sla" in k})
    st.dataframe(df[["alert_id", "created_at", "detected_at", "acknowledged_at", "responded_at", "timestamp_source", "risk_level"]], hide_index=True, use_container_width=True)


def render_compare() -> None:
    st.title("Traditional vs AI SOC Comparison")
    C.synthetic_banner()
    s = C.read_json(config.SOC_CMP_DIR / "comparison_summary.json")
    if not s:
        st.info("Run `python scripts/run_experiments.py` or System Configuration -> setup.")
        return
    st.caption(f"Workload: {s['workload']}. Identical data for every configuration.")
    df = pd.DataFrame(s["table"])
    st.dataframe(df.set_index("config"), use_container_width=True)
    st.markdown(f"<div class='okbox'><b>LLM credit policy:</b> {s['llm_detection_credit']}</div>", unsafe_allow_html=True)
    p = config.SOC_CMP_DIR
    a, b = st.columns(2)
    with a:
        C.show_image(p / "detection_comparison.png")
    with b:
        C.show_image(p / "operational_comparison.png")
    C.show_image(p / "category_recall.png")
    sw = p / "threshold_sweep.csv"
    if sw.exists():
        st.subheader("Config D: sensitivity to the risk alert-gate")
        t = pd.read_csv(sw)
        st.dataframe(t, hide_index=True, use_container_width=True)
        st.plotly_chart(px.line(t, x="risk_threshold", y=["precision", "recall", "f1", "alert_reduction_vs_A"], markers=True), use_container_width=True)
    st.write("Endpoint (Sysmon/auth.log) rule-only performance:", s["endpoint_rules_only"])
    st.subheader("Assumptions")
    st.json(s["assumptions"])

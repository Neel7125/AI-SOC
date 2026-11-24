"""AI-SOC Streamlit dashboard.  Run: streamlit run app.py"""
import streamlit as st

import config  # noqa: F401  (loads .env, creates folders)
from dashboard import alerts, common, investigation, llm_analytics, mitre, ml_analytics, monitoring, overview, reports, risk, soc_perf, system

st.set_page_config(page_title="AI-SOC", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")
st.markdown(common.CSS, unsafe_allow_html=True)

PAGES = {
    "SOC Overview": overview.render, "Live Security Monitoring": monitoring.render, "Alert Management": alerts.render,
    "ML Threat Detection": ml_analytics.render_detection, "Anomaly Detection": ml_analytics.render_anomaly,
    "AI Incident Investigation": investigation.render, "Risk Assessment": risk.render, "MITRE ATT&CK Explorer": mitre.render,
    "ML Model Evaluation": ml_analytics.render_eval, "LLM Evaluation": llm_analytics.render,
    "SOC Performance Analytics": soc_perf.render_perf, "Traditional vs AI SOC Comparison": soc_perf.render_compare,
    "Incident Reports": reports.render, "System Configuration": system.render,
}
st.sidebar.title("🛡️ AI-SOC")
st.sidebar.caption("AI-driven Security Operations Center")
page = st.sidebar.radio("Navigate", list(PAGES))
PAGES[page]()

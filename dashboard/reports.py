from __future__ import annotations

import streamlit as st

import config
from dashboard import common as C
from reporting.academic_report import build_academic_report
from reporting.incident_report import build_report, to_json, to_pdf


def render() -> None:
    st.title("Incident Reports")
    if not C.guard():
        return
    df = C.sidebar_filters(C.alerts_df())
    if df.empty:
        st.info("No incidents.")
        return
    aid = st.selectbox("Incident", df.alert_id.tolist(), format_func=lambda x: f"{x} | {df[df.alert_id == x].title.iloc[0]}")
    rep = build_report(aid)
    st.markdown(f"**{rep['title']}** - {rep['risk_level']} ({rep['risk_score']}) - status {rep['final_status']}")
    if rep["llm_investigation"] is None:
        st.info("No AI investigation stored yet - run one in 'AI Incident Investigation' to include it in the report.")
    st.json(rep, expanded=False)
    c1, c2 = st.columns(2)
    jp, pp = to_json(rep), to_pdf(rep)
    c1.download_button("Download JSON", jp.read_bytes(), file_name=jp.name, mime="application/json")
    c2.download_button("Download PDF", pp.read_bytes(), file_name=pp.name, mime="application/pdf")
    st.divider()
    st.subheader("Academic experiment report")
    if st.button("Build / refresh academic report"):
        try:
            st.success(build_academic_report())
        except FileNotFoundError as e:
            st.error(str(e))
    md, pdf = config.REPORTS_DIR / "academic_report.md", config.REPORTS_DIR / "academic_report.pdf"
    if pdf.exists():
        a, b = st.columns(2)
        a.download_button("Download academic report (PDF)", pdf.read_bytes(), file_name=pdf.name)
        b.download_button("Download academic report (Markdown)", md.read_bytes(), file_name=md.name)

from __future__ import annotations

import json

import pandas as pd
import plotly.express as px
import streamlit as st

import config
from dashboard import common as C
from database import repository as repo
from risk_engine.risk_calculator import COMPONENTS, RiskInputs, calculate, validate_weights


def render() -> None:
    st.title("Risk Assessment")
    st.latex(r"Risk = 0.30\,Severity + 0.25\,Impact + 0.20\,MLConf + 0.15\,AssetCrit + 0.10\,Exploit")
    st.caption("All inputs are 0-100. Levels: 0-20 Informational, 21-40 Low, 41-60 Medium, 61-80 High, 81-100 Critical. "
               "Optional context (CVSS, EPSS, threat intel, recurrence, ATT&CK tactic) adds at most +10 points. CVSS describes a vulnerability, not incident risk.")
    st.markdown("**Default weights** " + ", ".join(f"{k}={v}" for k, v in config.RISK_WEIGHTS.items()))
    with st.expander("Interactive calculator (configurable weights)", expanded=True):
        w = {}
        cols = st.columns(5)
        for i, n in enumerate(COMPONENTS):
            w[n] = cols[i].number_input(f"w_{n}", 0.0, 1.0, float(config.RISK_WEIGHTS[n]), 0.05)
        try:
            validate_weights(w)
        except ValueError as e:
            st.error(f"Invalid weights: {e}")
        cols = st.columns(5)
        vals = {n: cols[i].slider(n, 0, 100, 50) for i, n in enumerate(COMPONENTS)}
        o = st.columns(4)
        cvss = o[0].number_input("CVSS (0-10, optional)", 0.0, 10.0, 0.0); epss = o[1].number_input("EPSS (0-1)", 0.0, 1.0, 0.0)
        ti = o[2].number_input("Threat intel reputation (0-100)", 0, 100, 0); rec = o[3].number_input("Prior recurrences", 0, 50, 0)
        try:
            res = calculate(RiskInputs(**vals, cvss=cvss or None, epss=epss or None, ti_reputation=ti or None, recurrence=rec or None), w)
            st.metric("Risk score", f"{res['score']} - {res['level']}")
            st.write(res["explanation"])
            st.plotly_chart(px.bar(pd.DataFrame(res["components"]).T.reset_index(), x="contribution", y="index", orientation="h", title="Contribution per component"), use_container_width=True)
        except ValueError as e:
            st.error(str(e))
    if not C.guard():
        return
    df = C.sidebar_filters(C.alerts_df())
    c1, c2 = st.columns(2)
    c1.plotly_chart(px.histogram(df, x="risk_score", nbins=30, color="risk_level", color_discrete_map=C.RISK_COLORS, title="Risk score distribution"), use_container_width=True)
    c2.plotly_chart(px.box(df, x="attack_category", y="risk_score", title="Risk by category"), use_container_width=True)
    st.subheader("Prioritised queue")
    st.dataframe(df.sort_values("risk_score", ascending=False).head(25)[["alert_id", "title", "risk_score", "risk_level", "severity", "impact", "asset_criticality", "exploitability", "ml_confidence", "risk_overridden"]], hide_index=True, use_container_width=True)
    if len(df):
        aid = st.selectbox("Risk history for", df.alert_id.tolist())
        st.dataframe(repo.get_risk_history(aid), hide_index=True, use_container_width=True)

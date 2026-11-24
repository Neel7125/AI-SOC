from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

import config
from dashboard import common as C
from database import repository as repo


def render() -> None:
    st.title("SOC Overview")
    C.synthetic_banner()
    if not C.guard():
        return
    full = C.alerts_df()
    df = C.sidebar_filters(full)
    events = repo.query_df("SELECT COUNT(*) n, SUM(gt_label=1) mal, SUM(gt_label=0) ben FROM events").iloc[0]
    cmp_ = C.read_json(config.SOC_CMP_DIR / "comparison_summary.json")
    open_ = df[~df.status.isin(["Resolved", "Closed"])]
    a = st.columns(5)
    a[0].metric("Total security events", f"{int(events.n):,}")
    a[1].metric("Total incidents (alerts)", f"{len(df):,}")
    a[2].metric("Malicious events (ground truth)", f"{int(events.mal or 0):,}")
    a[3].metric("Benign events (ground truth)", f"{int(events.ben or 0):,}")
    a[4].metric("Open incidents", f"{len(open_):,}")
    b = st.columns(5)
    b[0].metric("Critical incidents", int((df.risk_level == "Critical").sum()))
    b[1].metric("High-risk incidents", int((df.risk_level == "High").sum()))
    gt = df.dropna(subset=["gt_label"])
    fpr_inc = (gt.gt_label == 0).mean() if len(gt) else float("nan")
    b[2].metric("False-positive incident share", f"{fpr_inc:.1%}", help="Incidents whose events were all benign per synthetic ground truth")
    if cmp_:
        d = next(r for r in cmp_["table"] if r["config"] == "D")
        b[3].metric("Detection rate (config D)", f"{d['recall']:.1%}", help="Event-level recall on the unseen workload (experiment output)")
        b[4].metric("FPR (config D)", f"{d['false_positive_rate']:.2%}")
    else:
        b[3].metric("Detection rate", "n/a"); b[4].metric("FPR", "n/a")
        st.caption("Run experiments to populate detection rate / FPR.")
    if df.empty:
        st.info("No incidents match the filters.")
        return
    c1, c2 = st.columns(2)
    lv = df.risk_level.value_counts().reindex(C.LEVEL_ORDER).dropna().reset_index()
    lv.columns = ["risk_level", "incidents"]
    c1.plotly_chart(px.bar(lv, x="risk_level", y="incidents", color="risk_level", color_discrete_map=C.RISK_COLORS, title="Incidents by risk level"), use_container_width=True)
    c2.plotly_chart(px.pie(df, names="attack_category", title="Incidents by attack category", hole=.45), use_container_width=True)
    tl = df.set_index("created_at").resample("1h").size().reset_index(name="incidents")
    st.plotly_chart(px.area(tl, x="created_at", y="incidents", title="Incident timeline (hourly)"), use_container_width=True)
    c3, c4 = st.columns(2)
    c3.plotly_chart(px.histogram(df, x="detection_method", color="status", title="Detection method vs status"), use_container_width=True)
    c4.plotly_chart(px.scatter(df, x="created_at", y="risk_score", color="risk_level", size="event_count", color_discrete_map=C.RISK_COLORS,
                               hover_data=["alert_id", "title"], title="Risk over time (size = events)"), use_container_width=True)
    st.subheader("Recent / highest-risk alerts")
    st.dataframe(df.sort_values("created_at", ascending=False).head(15)[["alert_id", "created_at", "title", "risk_score", "risk_level", "detection_method", "status"]], use_container_width=True, hide_index=True)

from __future__ import annotations

import json

import pandas as pd
import plotly.express as px
import streamlit as st

import config
from dashboard import common as C
from database import repository as repo


def render() -> None:
    st.title("Alert Management")
    if not C.guard():
        return
    df = C.sidebar_filters(C.alerts_df())
    st.caption(f"{len(df)} incidents (sorted by risk). Select one below to manage it.")
    show = df[["alert_id", "created_at", "title", "risk_score", "risk_level", "detection_method", "attack_category", "status", "event_count", "risk_overridden"]]
    st.dataframe(show, use_container_width=True, hide_index=True, height=300)
    if df.empty:
        return
    aid = st.selectbox("Incident", df.alert_id.tolist(), format_func=lambda x: f"{x} | {df[df.alert_id == x].title.iloc[0]} | risk {df[df.alert_id == x].risk_score.iloc[0]:.0f}")
    a = repo.get_alert(aid)
    actor = st.sidebar.text_input("Analyst name (for audit trail)", "analyst1")
    left, right = st.columns([3, 2])
    with left:
        st.subheader(a["title"])
        st.markdown(f"{C.badge(a['risk_level'])} &nbsp; status **{a['status']}** &nbsp; risk **{a['risk_score']:.1f}**" + (" *(analyst override)*" if a["risk_overridden"] else ""), unsafe_allow_html=True)
        st.write({k: a[k] for k in ("created_at", "detected_at", "source", "src_ip", "dst_ip", "hostname", "username", "detection_method", "rule_names", "ml_model", "ml_prediction", "ml_confidence", "anomaly_score", "event_count", "timestamp_source")})
        ev = repo.get_event(a["event_id"])
        if ev:
            st.markdown("**Representative event**"); st.code(ev["description"])
        comp = json.loads(a["risk_components_json"] or "{}")
        if comp.get("components"):
            cdf = pd.DataFrame(comp["components"]).T.reset_index().rename(columns={"index": "component"})
            st.plotly_chart(px.bar(cdf, x="contribution", y="component", orientation="h", title=f"Risk contribution breakdown (base {comp['base_score']}, context +{comp['context_adjustment']})"), use_container_width=True)
        st.markdown("**MITRE ATT&CK (detection-derived)**")
        st.dataframe(pd.DataFrame(json.loads(a["mitre_json"] or "[]")), hide_index=True, use_container_width=True)
    with right:
        st.markdown("#### Actions (human-approved only)")
        nxt = sorted(repo.ALLOWED_TRANSITIONS[a["status"]])
        if nxt:
            ns = st.selectbox("Change status", nxt)
            if st.button("Apply status change"):
                try:
                    repo.update_status(aid, ns, actor); st.success(f"{a['status']} -> {ns}"); st.rerun()
                except ValueError as e:
                    st.error(str(e))
        else:
            st.info("Closed - no further transitions.")
        note = st.text_area("Investigation note")
        if st.button("Add note"):
            try:
                repo.add_note(aid, actor, note); st.success("Note added")
            except ValueError as e:
                st.error(str(e))
        evi = st.text_input("Add evidence")
        if st.button("Add evidence"):
            try:
                repo.add_evidence(aid, actor, evi); st.success("Evidence added")
            except ValueError as e:
                st.error(str(e))
        st.markdown("**Override risk score**")
        sc = st.slider("New score", 0.0, 100.0, float(a["risk_score"]))
        just = st.text_input("Justification (required)")
        if st.button("Override"):
            try:
                repo.override_risk(aid, sc, just, actor); st.success("Overridden and logged"); st.rerun()
            except ValueError as e:
                st.error(str(e))
        lvl = st.selectbox("Assign severity level", list(C.LEVEL_ORDER))
        if st.button("Assign severity"):
            repo.set_severity_label(aid, lvl, actor); st.rerun()
        st.caption("The system never isolates hosts or disables accounts automatically.")
    t1, t2, t3, t4 = st.tabs(["Notes", "Evidence", "Risk history", "Audit trail"])
    t1.dataframe(repo.get_notes(aid), use_container_width=True, hide_index=True)
    t2.dataframe(repo.get_evidence(aid), use_container_width=True, hide_index=True)
    t3.dataframe(repo.get_risk_history(aid), use_container_width=True, hide_index=True)
    t4.dataframe(repo.get_audit(aid), use_container_width=True, hide_index=True)
    inv = repo.get_investigations(aid)
    if not inv.empty:
        st.markdown("#### Latest AI recommendations")
        r = json.loads(inv.iloc[0].response_json)
        st.write(r["incident_summary"]); st.write(r["recommended_actions"])

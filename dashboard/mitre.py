from __future__ import annotations

import json

import pandas as pd
import plotly.express as px
import streamlit as st

from dashboard import common as C
from mitre.knowledge_base import get_kb, tactics


def render() -> None:
    st.title("MITRE ATT&CK Explorer")
    kb = get_kb()
    st.caption(f"{len(kb)} techniques loaded (curated subset; drop enterprise-attack.json into data/raw for the full matrix). Mappings come from detection rules/classification, validated against this knowledge base - never from LLM guesses alone.")
    mapping = []
    if C.ready()[0]:
        for a in C.sidebar_filters(C.alerts_df()).to_dict("records"):
            for m in json.loads(a["mitre_json"] or "[]"):
                mapping.append({"incident": a["alert_id"], "technique_id": m["id"], "technique": m["name"], "tactic": m["tactic"], "category": a["attack_category"], "risk": a["risk_score"], "host": a["hostname"]})
    mp = pd.DataFrame(mapping)
    rows = []
    for t in kb.values():
        n = int((mp.technique_id == t["id"]).sum()) if len(mp) else 0
        rows.append({"tactic": t["tactic"], "technique": f"{t['id']} {t['name']}", "incidents": n, "has_detection": n > 0})
    cov = pd.DataFrame(rows)
    cov["tactic"] = pd.Categorical(cov["tactic"], categories=tactics(), ordered=True)
    fig = px.treemap(cov.sort_values("tactic"), path=["tactic", "technique"], values=cov["incidents"].clip(lower=0) + 0.3, color="incidents",
                     color_continuous_scale="Reds", title="ATT&CK coverage (colour = related incidents; grey area = knowledge-base only)")
    st.plotly_chart(fig, use_container_width=True)
    per = cov.groupby("tactic", observed=True).agg(techniques=("technique", "count"), observed_in_incidents=("has_detection", "sum")).reset_index()
    st.dataframe(per, hide_index=True, use_container_width=True)
    st.subheader("Incident-to-technique mapping")
    st.dataframe(mp, hide_index=True, use_container_width=True) if len(mp) else st.info("No incidents mapped.")
    st.subheader("Technique browser")
    q = st.text_input("Search technique / tactic / description")
    items = [t for t in kb.values() if q.lower() in (t["id"] + t["name"] + t["tactic"] + t["description"]).lower()]
    for t in items[:30]:
        with st.expander(f"{t['id']} - {t['name']} ({t['tactic']})"):
            st.write(t["description"])
            if len(mp):
                rel = mp[mp.technique_id == t["id"]]
                st.write(f"Related incidents: {len(rel)}"); st.dataframe(rel.head(10), hide_index=True)

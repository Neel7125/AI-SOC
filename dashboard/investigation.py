from __future__ import annotations

import pandas as pd
import streamlit as st

import config
from dashboard import common as C
from database import repository as repo
from llm_engine.investigation import answer_question, investigate
from llm_engine.llm_provider import Provider


def render() -> None:
    st.title("AI Incident Investigation")
    st.caption("Evidence-grounded, schema-validated, human-in-the-loop. Logs and retrieved documents are treated as untrusted data.")
    if not C.guard():
        return
    df = C.sidebar_filters(C.alerts_df())
    if df.empty:
        st.info("No incidents.")
        return
    aid = st.selectbox("Incident", df.alert_id.tolist(), format_func=lambda x: f"{x} | {df[df.alert_id == x].title.iloc[0]} | {df[df.alert_id == x].risk_level.iloc[0]}")
    c1, c2, c3, c4 = st.columns(4)
    opts = {p: Provider(p).available() for p in ("offline", "openai", "ollama")}
    prov = c1.selectbox("Provider", list(opts), format_func=lambda p: f"{p} ({'ready' if opts[p][0] else opts[p][1]})",
                        index=list(opts).index(config.LLM_PROVIDER) if config.LLM_PROVIDER in opts else 0)
    rag = c2.checkbox("Use RAG retrieval", True)
    task = c3.selectbox("Task", ["investigate", "explain_alert", "related_summary", "root_cause", "classify"])
    c4.write(""); run = c4.button("Run investigation", type="primary")
    if prov == "offline":
        st.markdown("<div class='warnbox'>Offline mode: a deterministic <b>template summariser</b> (not a language model) so the demo works without credentials. Select OpenAI or Ollama for real LLM output.</div>", unsafe_allow_html=True)
    if run:
        with st.spinner("Investigating..."):
            st.session_state[f"inv_{aid}"] = investigate(aid, provider=prov, use_rag=rag, task=task)
    rec = st.session_state.get(f"inv_{aid}")
    if rec:
        r = rec["response"]
        st.markdown(f"### {r['threat_type']} &nbsp; {C.badge(r['severity'])} &nbsp; risk {r['risk_score']:.1f}", unsafe_allow_html=True)
        st.write(r["incident_summary"])
        m = st.columns(5)
        m[0].metric("Provider / model", f"{rec['provider']}"); m[1].metric("Latency", f"{rec['latency_s']*1000:.1f} ms")
        m[2].metric("Tokens", rec["prompt_tokens"] + rec["completion_tokens"], help="estimated" if rec["tokens_estimated"] else "reported by API")
        m[3].metric("Est. cost", f"${rec['cost_usd']:.5f}"); m[4].metric("RAG used", "YES" if rec["rag_used"] else "NO")
        if not rec["valid_json"]:
            st.error("Provider output was not valid; offline template fallback used.")
        for w in rec["warnings"]:
            st.markdown(f"<div class='warnbox'>{w}</div>", unsafe_allow_html=True)
        a, b = st.columns(2)
        with a:
            st.markdown("**Confirmed facts** (cite evidence)"); [st.markdown(f"- {x}") for x in r["confirmed_facts"]]
            st.markdown("**Hypotheses** (unconfirmed)"); [st.markdown(f"- {x}") for x in r["hypotheses"]]
            st.markdown("**Evidence references**"); [st.markdown(f"- {x}") for x in r["evidence"]]
        with b:
            st.markdown("**MITRE ATT&CK**"); st.dataframe(pd.DataFrame(rec["mitre_validated"]), hide_index=True, use_container_width=True)
            st.markdown("**Investigation steps**"); [st.markdown(f"{i+1}. {x}") for i, x in enumerate(r["investigation_steps"])]
            st.markdown("**Recommended actions** (approval required)"); [st.markdown(f"- {x}") for x in r["recommended_actions"]]
        st.markdown(f"**Confidence:** {r['confidence']}  |  **Limitations:** {'; '.join(r['limitations'])}")
        st.subheader("Retrieved knowledge (RAG)")
        if rec["rag_used"]:
            for d in rec["retrieved_text"]:
                with st.expander(f"{d['source']} - {d['title']} (similarity {d['score']})"):
                    st.write(d["text"])
        else:
            st.info("No retrieval used for this answer.")
        with st.expander("Structured context sent to the model"):
            st.json(rec["context"])
    st.divider()
    st.subheader("Analyst Q&A")
    q = st.text_input("Ask a question (answers cite retrieved sources)", "How do I investigate an SSH brute force alert?")
    if st.button("Ask"):
        res = answer_question(q, aid if st.checkbox("Include selected incident", False) else None, prov)
        st.write(res["answer"]); st.caption(f"RAG used: {res['rag_used']}"); st.dataframe(pd.DataFrame(res["sources"]), hide_index=True)
    hist = repo.get_investigations(aid)
    if not hist.empty:
        st.subheader("Investigation audit (stored)")
        st.dataframe(hist[["ts", "provider", "model", "rag_used", "latency_s", "prompt_tokens", "completion_tokens", "cost_usd", "valid_json"]], hide_index=True, use_container_width=True)

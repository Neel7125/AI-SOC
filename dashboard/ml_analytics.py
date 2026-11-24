from __future__ import annotations

import json

import pandas as pd
import plotly.express as px
import streamlit as st

import config
from dashboard import common as C
from database import repository as repo
from ml_engine import model_registry as reg


def render_detection() -> None:
    st.title("ML Threat Detection")
    C.synthetic_banner()
    if not C.guard():
        return
    r = reg.get_registry()
    rows = [{"model": n, "dataset": m.get("dataset"), "test macro-F1": m.get("test", {}).get("multiclass", {}).get("macro_f1"),
             "test binary F1": m.get("test", {}).get("binary", {}).get("f1"), "AUC-ROC": m.get("test", {}).get("binary", {}).get("auc_roc"),
             "train s": m.get("train_seconds"), "registered": m.get("registered_at")} for n, m in r["models"].items()]
    st.markdown(f"Active model (best by validation macro-F1): **{r['best']}**. Models are loaded from disk; the dashboard never retrains automatically.")
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    df = C.alerts_df()
    ml = df[df.ml_model.fillna("").str.startswith(("random", "xgb", "logistic"))]
    c1, c2 = st.columns(2)
    c1.plotly_chart(px.histogram(ml, x="ml_prediction", color="risk_level", color_discrete_map=C.RISK_COLORS, title="ML predicted categories (incidents)"), use_container_width=True)
    c2.plotly_chart(px.histogram(ml, x="ml_confidence", nbins=25, title="ML malicious probability (P(any attack class))"), use_container_width=True)
    st.subheader("Try the classifier on a live-workload flow")
    live = pd.read_csv(config.SYNTH_DIR / "live_flows.csv")
    idx = st.number_input("Flow row", 0, len(live) - 1, 5)
    row = live.iloc[int(idx)]
    st.write(row[["flow_id", "src_ip", "dst_ip", "dst_port", "duration", "fwd_pkts", "bwd_pkts", "fwd_bytes", "pkts_per_s"]].to_dict())
    if st.button("Classify flow"):
        res = C.get_predictor().predict_one(row.to_dict())
        st.json({k: (round(v, 4) if isinstance(v, float) else v) for k, v in res.items()})
        st.caption(f"Ground-truth (synthetic label): {row['attack_category']}")


def render_anomaly() -> None:
    st.title("Anomaly Detection (Isolation Forest)")
    st.markdown("<div class='warnbox'><b>Anomaly score &ne; maliciousness.</b> The score is the percentile of unusualness versus benign training traffic (0-100). "
                "Anomalies include harmless events (backups, scanners) - they are leads, not confirmed attacks.</div>", unsafe_allow_html=True)
    if not C.guard():
        return
    iso = C.get_predictor().iso
    st.write(f"Anomaly threshold: percentile **{iso.threshold_pct}** of benign-train scores (configurable in `ml_engine/isolation_forest.py` / retrain).")
    df = C.alerts_df()
    d = df.dropna(subset=["anomaly_score"])
    st.plotly_chart(px.histogram(d, x="anomaly_score", color=d.gt_label.map({0: "benign (synthetic GT)", 1: "malicious (synthetic GT)"}), nbins=40, barmode="overlay",
                                 title="Anomaly score distribution of incident representatives"), use_container_width=True)
    thr = st.slider("Display threshold", 0.0, 100.0, float(iso.threshold_pct))
    sus = d[d.anomaly_score >= thr].sort_values("anomaly_score", ascending=False)
    st.metric("Records above threshold", len(sus))
    st.dataframe(sus[["alert_id", "title", "anomaly_score", "ml_prediction", "risk_level", "detection_method"]], hide_index=True, use_container_width=True)
    if len(sus):
        aid = st.selectbox("Explain why flagged", sus.alert_id.tolist())
        ev = repo.get_event(repo.get_alert(aid)["event_id"])
        feats = json.loads(ev["features_json"]) if ev and ev.get("features_json") else None
        if feats:
            pred = C.get_predictor()
            X = pred.pre.transform(pd.DataFrame([feats]))
            st.write(pred.iso.explain(X.iloc[0], top=4))


def render_eval() -> None:
    st.title("ML Model Evaluation")
    C.synthetic_banner()
    m = C.read_json(config.ML_EVAL_DIR / "evaluation_metrics.json")
    if not m:
        st.info("Run `python scripts/evaluate_all.py` (or System Configuration -> setup).")
        return
    st.caption(f"Held-out test set: {m['test_rows']} flows. Class counts: {m['test_class_counts']}. Best model: {m['best_model']}.")
    tbl = pd.DataFrame({k: v["binary"] for k, v in m["metrics"].items()}).T
    st.subheader("Binary detection metrics (malicious vs benign)")
    st.dataframe(tbl, use_container_width=True)
    st.subheader("Multiclass metrics")
    st.dataframe(pd.DataFrame({k: v["multiclass"] for k, v in m["metrics"].items() if "multiclass" in v}).T, use_container_width=True)
    tabs = st.tabs(["Confusion", "ROC / PR", "Features", "Comparison & learning", "Anomaly", "Report"])
    p = config.ML_EVAL_DIR
    with tabs[0]:
        a, b = st.columns(2); a.image(str(p / "confusion_matrix.png")); b.image(str(p / "normalized_confusion_matrix.png"))
        a, b = st.columns(2); a.image(str(p / "multiclass_confusion_matrix.png")); b.image(str(p / "multiclass_normalized_confusion_matrix.png"))
    with tabs[1]:
        a, b = st.columns(2); a.image(str(p / "roc_curve.png")); b.image(str(p / "precision_recall_curve.png"))
    with tabs[2]:
        a, b = st.columns(2); a.image(str(p / "feature_importance.png")); b.image(str(p / "feature_correlation.png"))
    with tabs[3]:
        a, b = st.columns(2); a.image(str(p / "model_comparison.png"))
        if (p / "learning_curve.png").exists():
            b.image(str(p / "learning_curve.png"))
    with tabs[4]:
        C.show_image(p / "anomaly_scores.png")
    with tabs[5]:
        st.dataframe(pd.read_csv(p / "classification_report.csv"), hide_index=True, use_container_width=True)

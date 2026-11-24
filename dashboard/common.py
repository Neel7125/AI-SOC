"""Shared dashboard helpers: theme, data access, global filters, setup guard."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.io as pio
import streamlit as st

import config
from database import repository as repo
from ml_engine import model_registry as reg

pio.templates.default = "plotly_dark"
RISK_COLORS = {"Informational": "#6c757d", "Low": "#2a9d8f", "Medium": "#e9c46a", "High": "#f4a261", "Critical": "#e63946"}
LEVEL_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]

CSS = """
<style>
.stApp {background:#0b1220;} [data-testid=stSidebar]{background:#0f1a2e;}
div[data-testid=stMetric]{background:#111c33;border:1px solid #1f2f52;border-radius:10px;padding:10px 14px;}
h1,h2,h3{color:#e6edf7;} .small{color:#8da2c0;font-size:.85rem;}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.8rem;font-weight:600;color:#0b1220;}
.warnbox{background:#2b2210;border-left:4px solid #e9c46a;padding:8px 12px;border-radius:6px;margin:6px 0;}
.okbox{background:#102b22;border-left:4px solid #2a9d8f;padding:8px 12px;border-radius:6px;margin:6px 0;}
</style>"""


def badge(level: str) -> str:
    return f"<span class='badge' style='background:{RISK_COLORS.get(level, '#888')}'>{level}</span>"


def ready() -> tuple[bool, list[str]]:
    miss = []
    if not (config.SYNTH_DIR / "live_flows.csv").exists():
        miss.append("synthetic data")
    if not reg.models_available():
        miss.append("trained models")
    if repo.count_events() == 0:
        miss.append("pipeline results in database")
    return not miss, miss


def guard() -> bool:
    ok, miss = ready()
    if not ok:
        st.warning(f"Not initialised yet: {', '.join(miss)}. Open **System Configuration** and press *Run full setup*, or run `python scripts/setup_demo.py`.")
    return ok


def alerts_df() -> pd.DataFrame:
    df = repo.list_alerts()
    if df.empty:
        return df
    for c in ("created_at", "detected_at", "acknowledged_at", "responded_at"):
        df[c] = pd.to_datetime(df[c], errors="coerce")
    return df


def sidebar_filters(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    with st.sidebar.expander("Filters", expanded=False):
        lo, hi = df["created_at"].min().date(), df["created_at"].max().date()
        dr = st.date_input("Date range", (lo, hi), min_value=lo, max_value=hi)
        sev = st.multiselect("Severity", LEVEL_ORDER)
        ip = st.text_input("Source IP contains")
        host = st.multiselect("Hostname", sorted(df["hostname"].dropna().unique()))
        cat = st.multiselect("Attack category", sorted(df["attack_category"].dropna().unique()))
        meth = st.multiselect("Detection method", sorted(df["detection_method"].dropna().unique()))
        stt = st.multiselect("Incident status", config.INCIDENT_STATUSES)
    out = df
    if isinstance(dr, tuple) and len(dr) == 2:
        out = out[(out.created_at.dt.date >= dr[0]) & (out.created_at.dt.date <= dr[1])]
    for col, vals in (("risk_level", sev), ("hostname", host), ("attack_category", cat), ("detection_method", meth), ("status", stt)):
        if vals:
            out = out[out[col].isin(vals)]
    if ip:
        out = out[out.src_ip.fillna("").str.contains(ip, regex=False)]
    return out


@st.cache_resource(show_spinner="Loading models...")
def get_predictor():
    from ml_engine.predict import Predictor
    return Predictor()


def read_json(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def show_image(path: Path, caption: str | None = None) -> None:
    if path.exists():
        st.image(str(path), caption=caption or path.stem.replace("_", " "), use_container_width=True)
    else:
        st.info(f"{path.name} not generated yet.")


def synthetic_banner() -> None:
    st.markdown("<div class='warnbox'>Demo data is <b>SYNTHETIC</b> (generated locally). Metrics describe this synthetic benchmark, not real-world performance.</div>", unsafe_allow_html=True)

"""Windowed correlation features (per source IP per time window)."""
from __future__ import annotations

import pandas as pd

WINDOW = "60s"


def add_flow_windows(df: pd.DataFrame, window: str = WINDOW) -> pd.DataFrame:
    """Adds per-(src_ip, window) aggregates used by scan / brute-force rules."""
    df = df.copy()
    df["win_start"] = df["timestamp"].dt.floor(window)
    g = df.groupby(["src_ip", "win_start"])
    df["win_unique_ports"] = g["dst_port"].transform("nunique")
    df["win_flow_count"] = g["flow_id"].transform("count") if "flow_id" in df else g["event_id"].transform("count")
    df["win_end"] = df["win_start"] + pd.Timedelta(window)
    ba = df[df["dst_port"].isin([22, 3389, 21])].groupby(["src_ip", "win_start", "dst_port"]).size().rename("win_auth_flows")
    df = df.merge(ba.reset_index(), on=["src_ip", "win_start", "dst_port"], how="left")
    df["win_auth_flows"] = df["win_auth_flows"].fillna(0)
    return df


def add_auth_windows(df: pd.DataFrame, window: str = "300s") -> pd.DataFrame:
    df = df.copy()
    df["win_start"] = df["timestamp"].dt.floor(window)
    failed = df[df["event_type"] == "ssh_login_failed"].groupby(["src_ip", "win_start"]).size().rename("win_failed_logins")
    df = df.merge(failed.reset_index(), on=["src_ip", "win_start"], how="left")
    df["win_failed_logins"] = df["win_failed_logins"].fillna(0)
    df["win_end"] = df["win_start"] + pd.Timedelta(window)
    return df

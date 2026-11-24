"""Configurable incident risk scoring.

Risk = w_s*Severity + w_i*Impact + w_c*MLConfidence + w_a*AssetCriticality + w_e*Exploitability
(all inputs on 0-100, default weights 0.30/0.25/0.20/0.15/0.10, summing to 1).

Optional context adjustment (capped at CONTEXT_MAX_BONUS points, then final score capped at 100):
  +3*CVSS/10  +2*EPSS  +3*TI_reputation/100  +min(3, 0.5*prior_recurrences)  +1 if tactic in {Impact, Exfiltration, Privilege Escalation}
CVSS/EPSS describe a *vulnerability*; they are never the incident risk itself - they only nudge it when supplied.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import config

LEVEL_MID = {"Informational": 10.0, "Low": 30.0, "Medium": 50.0, "High": 70.0, "Critical": 90.0}
COMPONENTS = ["severity", "impact", "ml_confidence", "asset_criticality", "exploitability"]


def classify(score: float) -> str:
    for upper, name in config.RISK_LEVELS:
        if score <= upper:
            return name
    return "Critical"


@dataclass
class RiskInputs:
    severity: float
    impact: float
    ml_confidence: float
    asset_criticality: float
    exploitability: float
    cvss: float | None = None            # 0-10
    epss: float | None = None            # 0-1
    ti_reputation: float | None = None   # 0-100 (higher = worse)
    recurrence: int | None = None
    mitre_tactic: str | None = None

    def validate(self) -> None:
        for n in COMPONENTS:
            v = getattr(self, n)
            if v is None or not 0 <= v <= 100:
                raise ValueError(f"{n} must be within 0-100 (got {v})")
        if self.cvss is not None and not 0 <= self.cvss <= 10:
            raise ValueError("cvss must be within 0-10")
        if self.epss is not None and not 0 <= self.epss <= 1:
            raise ValueError("epss must be within 0-1")
        if self.ti_reputation is not None and not 0 <= self.ti_reputation <= 100:
            raise ValueError("ti_reputation must be within 0-100")
        if self.recurrence is not None and self.recurrence < 0:
            raise ValueError("recurrence must be >= 0")


def validate_weights(w: dict[str, float]) -> None:
    if set(w) != set(COMPONENTS):
        raise ValueError(f"weights must define exactly {COMPONENTS}")
    if any(v < 0 for v in w.values()) or abs(sum(w.values()) - 1.0) > 1e-6:
        raise ValueError("weights must be non-negative and sum to 1.0")


def context_adjustment(i: RiskInputs) -> dict[str, float]:
    adj = {}
    if i.cvss is not None:
        adj["cvss"] = 3 * i.cvss / 10
    if i.epss is not None:
        adj["epss"] = 2 * i.epss
    if i.ti_reputation is not None:
        adj["threat_intel"] = 3 * i.ti_reputation / 100
    if i.recurrence:
        adj["recurrence"] = min(3.0, 0.5 * i.recurrence)
    if i.mitre_tactic in ("Impact", "Exfiltration", "Privilege Escalation"):
        adj["mitre_tactic"] = 1.0
    return adj


def calculate(i: RiskInputs, weights: dict[str, float] | None = None) -> dict:
    weights = weights or config.RISK_WEIGHTS
    validate_weights(weights)
    i.validate()
    comp = {n: {"value": float(getattr(i, n)), "weight": weights[n], "contribution": round(getattr(i, n) * weights[n], 3)} for n in COMPONENTS}
    base = sum(c["contribution"] for c in comp.values())
    adj = context_adjustment(i)
    adj_total = min(config.CONTEXT_MAX_BONUS, sum(adj.values()))
    score = round(min(100.0, base + adj_total), 2)
    return {"score": score, "level": classify(score), "base_score": round(base, 2), "context_adjustment": round(adj_total, 2),
            "context_detail": {k: round(v, 2) for k, v in adj.items()}, "components": comp,
            "explanation": "; ".join(f"{n}={c['value']:.0f}x{c['weight']:.2f}={c['contribution']:.1f}" for n, c in comp.items())
                           + (f"; context +{adj_total:.1f}" if adj_total else "")}

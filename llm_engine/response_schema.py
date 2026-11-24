"""Pydantic schema for validated LLM investigation output."""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

TID = re.compile(r"^T\d{4}(\.\d{3})?$")


class Investigation(BaseModel):
    incident_summary: str = Field(min_length=10)
    threat_type: str
    severity: Literal["Informational", "Low", "Medium", "High", "Critical"]
    risk_score: float = Field(ge=0, le=100)
    mitre_techniques: list[str] = []
    evidence: list[str] = []                     # every item must begin with an evidence reference such as [E3]
    investigation_steps: list[str] = []
    recommended_actions: list[str] = []
    confidence: float = Field(ge=0, le=1)
    limitations: list[str] = []
    confirmed_facts: list[str] = []              # facts directly supported by evidence
    hypotheses: list[str] = []                   # uncertain interpretations

    @field_validator("mitre_techniques")
    @classmethod
    def _tid(cls, v: list[str]) -> list[str]:
        return [t.strip() for t in v if TID.match(t.strip())]

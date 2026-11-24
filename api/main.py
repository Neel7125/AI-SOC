"""FastAPI backend. Run: uvicorn api.main:app --reload   (docs at /docs)"""
from __future__ import annotations

import json
from typing import Any

import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

import config
from database import repository as repo
from evaluation.soc_metrics import soc_metrics
from llm_engine.investigation import answer_question, investigate
from rag.retriever import retrieve
from reporting.incident_report import build_report, to_json, to_pdf
from risk_engine.risk_calculator import RiskInputs, calculate

app = FastAPI(title="AI-SOC API", version="1.0", description="Synthetic-data demo unless real sources are configured.")


class FlowFeatures(BaseModel):
    features: dict[str, float] = Field(description="Flow features: dst_port, duration, fwd_pkts, ... (missing ones are median-imputed)")


class StatusChange(BaseModel):
    status: str
    actor: str = "analyst"


class Note(BaseModel):
    author: str = "analyst"
    note: str


class Override(BaseModel):
    score: float = Field(ge=0, le=100)
    justification: str = Field(min_length=5)
    actor: str = "analyst"


class RiskReq(BaseModel):
    severity: float; impact: float; ml_confidence: float; asset_criticality: float; exploitability: float
    cvss: float | None = None; epss: float | None = None; ti_reputation: float | None = None; recurrence: int | None = None


class Question(BaseModel):
    question: str = Field(min_length=3)
    alert_id: str | None = None
    provider: str | None = None


def _clean(df: pd.DataFrame) -> list[dict]:
    return json.loads(df.to_json(orient="records"))


@app.get("/health")
def health() -> dict:
    from ml_engine.model_registry import models_available
    return {"status": "ok", "models_trained": models_available(), "events": repo.count_events(), "llm_provider": config.LLM_PROVIDER}


@app.get("/alerts")
def alerts(limit: int = 100, min_risk: float = 0, status: str | None = None) -> list[dict]:
    df = repo.list_alerts()
    df = df[df.risk_score >= min_risk]
    if status:
        df = df[df.status == status]
    return _clean(df.head(limit))


@app.get("/alerts/{alert_id}")
def alert(alert_id: str) -> dict[str, Any]:
    a = repo.get_alert(alert_id)
    if not a:
        raise HTTPException(404, "alert not found")
    return json.loads(json.dumps(a, default=str))


@app.post("/alerts/{alert_id}/status")
def status(alert_id: str, body: StatusChange) -> dict:
    try:
        repo.update_status(alert_id, body.status, body.actor)
    except (ValueError, KeyError) as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/alerts/{alert_id}/notes")
def note(alert_id: str, body: Note) -> dict:
    try:
        repo.add_note(alert_id, body.author, body.note)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/alerts/{alert_id}/override-risk")
def override(alert_id: str, body: Override) -> dict:
    try:
        repo.override_risk(alert_id, body.score, body.justification, body.actor)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


@app.post("/predict")
def predict(req: FlowFeatures) -> dict:
    from ml_engine.predict import Predictor
    try:
        r = Predictor().predict_one(req.features)
    except FileNotFoundError as e:
        raise HTTPException(503, str(e))
    return {k: (v if not hasattr(v, "item") else v.item()) for k, v in r.items()}


@app.post("/investigate/{alert_id}")
def investigate_alert(alert_id: str, provider: str | None = None, use_rag: bool = True) -> dict:
    try:
        rec = investigate(alert_id, provider=provider, use_rag=use_rag)
    except KeyError:
        raise HTTPException(404, "alert not found")
    rec.pop("retrieved_text", None)
    return json.loads(json.dumps(rec, default=str))


@app.post("/ask")
def ask(q: Question) -> dict:
    return answer_question(q.question, q.alert_id, q.provider)


@app.get("/rag/search")
def rag_search(q: str, k: int = 4) -> list[dict]:
    return retrieve(q, k=k)


@app.post("/risk/calculate")
def risk(req: RiskReq) -> dict:
    try:
        return calculate(RiskInputs(**req.model_dump()))
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.get("/metrics/soc")
def metrics() -> dict:
    return soc_metrics(repo.list_alerts())


@app.get("/reports/{alert_id}.{fmt}")
def report(alert_id: str, fmt: str):
    try:
        rep = build_report(alert_id)
    except KeyError:
        raise HTTPException(404, "alert not found")
    if fmt == "json":
        return FileResponse(to_json(rep), media_type="application/json")
    if fmt == "pdf":
        return FileResponse(to_pdf(rep), media_type="application/pdf")
    raise HTTPException(400, "fmt must be json or pdf")

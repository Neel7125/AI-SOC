"""LLM investigation workflow with guardrails: grounding, validation, MITRE verification, human-approval policy, audit."""
from __future__ import annotations

import json
import logging
import re
import time

from pydantic import ValidationError

import config
from database import repository as repo
from llm_engine.llm_provider import Provider, offline_complete
from llm_engine.openai_client import LLMError
from llm_engine.prompts import build_context, build_messages
from llm_engine.response_schema import Investigation
from mitre import attack_mapping
from rag.retriever import retrieve

log = logging.getLogger(__name__)
DESTRUCTIVE = re.compile(r"\b(isolat|disabl|block|delet|kill|shut ?down|quarantin|reset|terminat|remov|wipe|rebuild|restrict|enforce|enable)", re.I)
REF = re.compile(r"^\[(E\d+)\]")
_RULE_RE = re.compile(r"\{.*\}", re.S)


def _extract_json(text: str) -> dict:
    m = _RULE_RE.search(text or "")
    if not m:
        raise ValueError("no JSON object in response")
    return json.loads(m.group(0))


def cost_estimate(provider: str, model: str, pt: int, ct: int) -> float:
    if provider != "openai":
        return 0.0                                       # local/offline providers: no API cost
    pi, po = config.LLM_PRICES.get(model, (0.0, 0.0))
    return round((pt * pi + ct * po) / 1e6, 6)


def build_query(alert: dict, event: dict | None) -> str:
    return " ".join(str(x) for x in (alert.get("attack_category"), alert.get("ml_prediction"), alert.get("rule_names"),
                                     (event or {}).get("description"), alert.get("title")) if x and str(x) not in ("BENIGN", "nan"))


def guard(resp: dict, E: dict[str, str], alert: dict, det_mitre: list[str], retrieved: list[dict]) -> tuple[dict, list[dict], list[str]]:
    """Post-process the model output so conclusions stay grounded and non-destructive."""
    warns: list[str] = []
    ev_ok = []
    for e in resp.get("evidence", []):
        m = REF.match(str(e))
        if m and m.group(1) in E:
            ev_ok.append(e)
        else:
            warns.append(f"dropped ungrounded evidence item: {str(e)[:60]}")
    resp["evidence"] = ev_ok
    if not ev_ok:
        resp["confidence"] = min(resp.get("confidence", 0.3), 0.3)
        warns.append("no grounded evidence; confidence capped")
    # facts must also cite evidence
    resp["confirmed_facts"] = [f for f in resp.get("confirmed_facts", []) if REF.match(str(f)) and REF.match(str(f)).group(1) in E] or []
    mitre = attack_mapping.validate_suggestions(resp.get("mitre_techniques", []))
    for m in mitre:
        if m["id"] in det_mitre:
            m["status"] = "detection-derived (verified by rule/category mapping)"
        if m["status"].startswith("rejected"):
            warns.append(f"MITRE id {m['id']} rejected: not in knowledge base")
    resp["mitre_techniques"] = [m["id"] for m in mitre if not m["status"].startswith("rejected")]
    mitre = [m for m in mitre if not m["status"].startswith("rejected")]
    acts = []
    for a in resp.get("recommended_actions", []):
        acts.append(f"{a} [REQUIRES HUMAN APPROVAL - not executed]" if DESTRUCTIVE.search(a) else a)
    resp["recommended_actions"] = acts
    resp["risk_score"] = float(alert.get("risk_score") or 0)                  # computed by risk engine, never by the LLM
    if resp.get("severity") != alert.get("risk_level"):
        warns.append(f"LLM severity '{resp.get('severity')}' replaced by risk-engine level '{alert.get('risk_level')}'")
        resp["severity"] = alert.get("risk_level") or resp.get("severity")
    lim = resp.setdefault("limitations", [])
    lim.append("No response action has been executed; all actions need analyst approval.")
    if not retrieved:
        lim.append("Answer generated WITHOUT retrieval (RAG not used).")
    return resp, mitre, warns


def investigate(alert_id: str | None = None, alert: dict | None = None, event: dict | None = None, provider: str | None = None,
                model: str | None = None, use_rag: bool = True, task: str = "investigate", question: str | None = None,
                save: bool = True, related: list[dict] | None = None) -> dict:
    alert = alert or repo.get_alert(alert_id)
    if alert is None:
        raise KeyError(f"Alert {alert_id} not found")
    event = event if event is not None else repo.get_event(alert["event_id"])
    if related is None:
        rel = repo.query_df("SELECT alert_id, created_at, attack_category, risk_score FROM alerts WHERE src_ip=? AND alert_id<>? ORDER BY risk_score DESC LIMIT 5",
                            (alert.get("src_ip"), alert["alert_id"]))
        related = rel.to_dict("records")
    det_mitre = [m["id"] for m in json.loads(alert.get("mitre_json") or "[]")]
    ctx, E, flags = build_context(alert, event, related, det_mitre)
    retrieved = retrieve(build_query(alert, event), log_to_db=save) if use_rag else []
    msgs = build_messages(ctx, retrieved, task, question)
    prov = Provider(provider, model)
    warnings = [f"prompt-injection pattern redacted in field(s): {', '.join(flags)}"] if flags else []
    t0 = time.perf_counter()
    valid, used_name = True, prov.name
    try:
        raw = prov.complete(msgs)
        parsed = Investigation(**_extract_json(raw["text"]))
    except (LLMError, ValueError, ValidationError, KeyError) as exc:
        log.warning("LLM path failed (%s); falling back to offline template", type(exc).__name__)
        valid = False
        warnings.append(f"{prov.name} output unusable ({type(exc).__name__}: {str(exc)[:120]}); offline template used")
        raw = offline_complete(msgs); used_name = "offline"
        parsed = Investigation(**json.loads(raw["text"]))
    latency = time.perf_counter() - t0
    resp, mitre, gw = guard(parsed.model_dump(), E, alert, det_mitre, retrieved)
    warnings += gw
    rec = {"provider": used_name, "model": raw["model"], "rag_used": bool(retrieved), "response": resp, "mitre_validated": mitre,
           "latency_s": round(latency, 4), "prompt_tokens": raw["prompt_tokens"], "completion_tokens": raw["completion_tokens"],
           "tokens_estimated": raw["tokens_estimated"], "cost_usd": cost_estimate(used_name, raw["model"], raw["prompt_tokens"], raw["completion_tokens"]),
           "valid_json": valid, "retrieval": [{k: r[k] for k in ("chunk_id", "source", "title", "score")} for r in retrieved],
           "retrieved_text": retrieved, "warnings": warnings, "context": ctx, "evidence_items": E, "task": task}
    if save:
        repo.save_investigation(alert["alert_id"], rec)
    return rec


def answer_question(question: str, alert_id: str | None = None, provider: str | None = None, use_rag: bool = True) -> dict:
    """Analyst Q&A: grounded in retrieved knowledge (and the alert, when given). Returns sources."""
    retrieved = retrieve(question) if use_rag else []
    if alert_id:
        inv = investigate(alert_id, provider=provider, use_rag=use_rag, task="investigate", question=question, save=False)
        ans = inv["response"]["incident_summary"]
    else:
        ans = "\n".join(f"- {r['text'][:300]}" for r in retrieved[:2]) or "No relevant knowledge-base content found."
    return {"answer": ans, "rag_used": bool(retrieved), "sources": [{k: r[k] for k in ("source", "title", "score")} for r in retrieved]}

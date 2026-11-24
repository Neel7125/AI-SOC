"""Provider abstraction. 'offline' is a deterministic TEMPLATE summariser (NOT a language model) so the
whole app works without credentials; it is always labelled as such in outputs and evaluations."""
from __future__ import annotations

import json
import re

import config
from llm_engine import ollama_client, openai_client
from llm_engine.openai_client import LLMError

OFFLINE_MODEL = "offline-template-v1 (no LLM)"
_CTX = re.compile(r"<<<CONTEXT_JSON\n(.*?)\nCONTEXT_JSON>>>", re.S)
_RET = re.compile(r"<<<RETRIEVED\n(.*?)\nRETRIEVED>>>", re.S)

GENERIC_STEPS = ["Review the alert fields and raw event for the evidence listed.", "Check whether the source and asset are known/authorised.",
                 "Search for other events from the same source and host."]


def _steps_from_playbook(text: str) -> tuple[list[str], list[str]]:
    steps = re.findall(r"^\d\.\s+(.*)$", text, flags=re.M)
    m = re.search(r"Response \(requires human approval\):\s*(.*?)(?:\n|$)", text)
    actions = [a.strip().capitalize() for a in re.split(r",\s*", m.group(1).rstrip(".")) if a.strip()] if m else []
    return steps, actions


def offline_complete(messages: list[dict]) -> dict:
    user = messages[-1]["content"]
    ctx = json.loads(_CTX.search(user).group(1))
    ret = json.loads(_RET.search(user).group(1))
    E = ctx["evidence_items"]
    cat = ctx.get("ml_classification") if ctx.get("ml_classification") not in (None, "BENIGN", "n/a") else None
    rule = ctx.get("detection_rule") or ""
    threat = cat or ("Rule-detected activity" if "none" not in rule else "Anomalous activity")
    for key, label in (("scan", "PortScan"), ("flood", "DoS"), ("brute", "BruteForce"), ("outbound", "Exfiltration"), ("powershell", "PowerShell Abuse"),
                       ("privilege", "Privilege Escalation"), ("file", "Suspicious File Activity"), ("suspicious port", "C2 Connection")):
        if key in rule.lower() and not cat:
            threat = label
    steps, actions, mitre, docs = [], [], list(ctx.get("detection_mitre") or []), []
    for r in ret:
        if r["source"] == "playbooks.md" and not steps:
            steps, actions = _steps_from_playbook(r["text"] + "\n" + r["title"])
            docs.append(r["title"])
        if r["source"] == "MITRE ATT&CK":
            tid = r["title"].split()[0]
            if tid not in mitre and len(mitre) < 4:
                mitre.append(tid)
    # playbook chunks are split at word limits -> also scan retrieved playbook text for steps/actions
    if not steps:
        for r in ret:
            s2, a2 = _steps_from_playbook(r["text"])
            steps, actions = steps or s2, actions or a2
    rag = bool(ret)
    facts = [f"[E1] {E['E1']}", f"[E3] {E['E3']}", f"[E6] {E['E6']}"]
    hyp = [f"The activity may be {threat} (ML: {ctx.get('ml_classification')}, anomaly score {ctx.get('anomaly_score')}); not confirmed without analyst validation."]
    out = {"incident_summary": f"{threat} observed from {ctx.get('source_ip') or 'unknown source'} against {ctx.get('hostname')}. "
                               f"Detection: {rule}. Risk {ctx.get('risk_score')} ({ctx.get('risk_level')}).",
           "threat_type": threat, "severity": ctx.get("risk_level") or "Low", "risk_score": float(ctx.get("risk_score") or 0),
           "mitre_techniques": mitre, "evidence": [f"[{k}] {v}" for k, v in E.items() if k in ("E1", "E2", "E3", "E4", "E5", "E6", "E7")],
           "investigation_steps": steps or GENERIC_STEPS, "recommended_actions": actions or ["Escalate to a senior analyst for review"],
           "confidence": round(min(0.9, 0.35 + 0.5 * float(ctx.get("ml_confidence") or 0.3)), 2),
           "limitations": ["Offline template summariser, not a language model.",
                           "Retrieved playbook guidance used." if rag else "No knowledge-base retrieval was used for this response."],
           "confirmed_facts": facts, "hypotheses": hyp}
    text = json.dumps(out)
    return {"text": text, "prompt_tokens": len(user) // 4, "completion_tokens": len(text) // 4, "model": OFFLINE_MODEL, "tokens_estimated": True}


class Provider:
    def __init__(self, name: str | None = None, model: str | None = None):
        self.name = name or config.LLM_PROVIDER
        self.model = model
        if self.name not in ("offline", "openai", "ollama"):
            raise ValueError(f"Unknown LLM provider '{self.name}'")

    def complete(self, messages: list[dict]) -> dict:
        if self.name == "openai":
            return openai_client.complete(messages, self.model)
        if self.name == "ollama":
            return ollama_client.complete(messages, self.model)
        return offline_complete(messages)

    def available(self) -> tuple[bool, str]:
        if self.name == "offline":
            return True, "always available"
        if self.name == "openai":
            return bool(config.OPENAI_API_KEY), "key set" if config.OPENAI_API_KEY else "OPENAI_API_KEY missing"
        ok = ollama_client.available()
        return ok, "reachable" if ok else "ollama not reachable"

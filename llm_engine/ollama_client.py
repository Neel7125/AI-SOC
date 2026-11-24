"""Ollama local-LLM client (e.g. `ollama pull llama3.1`).

Uses structured JSON output (Ollama >= 0.3 schema format) to guarantee the
response always matches the Investigation Pydantic schema, eliminating
ValidationError fallbacks from malformed model output.
"""
from __future__ import annotations

import requests

import config
from llm_engine.openai_client import LLMError

# JSON schema passed to Ollama's structured-output format field.
# Mirrors llm_engine/response_schema.py so the model is forced to produce
# every required key with the correct type.
_INVESTIGATION_SCHEMA = {
    "type": "object",
    "required": [
        "incident_summary", "threat_type", "severity", "risk_score",
        "mitre_techniques", "evidence", "investigation_steps",
        "recommended_actions", "confidence", "limitations",
        "confirmed_facts", "hypotheses"
    ],
    "properties": {
        "incident_summary":      {"type": "string"},
        "threat_type":           {"type": "string"},
        "severity":              {"type": "string", "enum": ["Informational", "Low", "Medium", "High", "Critical"]},
        "risk_score":            {"type": "number", "minimum": 0, "maximum": 100},
        "mitre_techniques":      {"type": "array",  "items": {"type": "string"}},
        "evidence":              {"type": "array",  "items": {"type": "string"}},
        "investigation_steps":   {"type": "array",  "items": {"type": "string"}},
        "recommended_actions":   {"type": "array",  "items": {"type": "string"}},
        "confidence":            {"type": "number", "minimum": 0, "maximum": 1},
        "limitations":           {"type": "array",  "items": {"type": "string"}},
        "confirmed_facts":       {"type": "array",  "items": {"type": "string"}},
        "hypotheses":            {"type": "array",  "items": {"type": "string"}},
    },
    "additionalProperties": False,
}


def available() -> bool:
    try:
        return requests.get(f"{config.OLLAMA_URL}/api/tags", timeout=2).ok
    except requests.RequestException:
        return False


def _supports_schema(model: str) -> bool:
    """Check whether the running Ollama instance supports structured JSON schema output."""
    try:
        r = requests.get(f"{config.OLLAMA_URL}/api/version", timeout=3)
        if not r.ok:
            return False
        version = r.json().get("version", "0.0.0")
        major, minor, *_ = (int(x) for x in version.split("."))
        return (major, minor) >= (0, 3)
    except Exception:
        return False


def complete(messages: list[dict], model: str | None = None, timeout: int = 300) -> dict:
    model = model or config.OLLAMA_MODEL

    # Prefer schema-constrained output (Ollama >= 0.3); fall back to plain
    # format="json" for older versions.
    use_schema = _supports_schema(model)
    fmt = _INVESTIGATION_SCHEMA if use_schema else "json"

    try:
        r = requests.post(
            f"{config.OLLAMA_URL}/api/chat",
            timeout=timeout,
            json={
                "model": model,
                "messages": messages,
                "stream": False,
                "format": fmt,
                "options": {"temperature": 0.1, "num_predict": 1024},
            },
        )
        r.raise_for_status()
    except requests.RequestException as exc:
        raise LLMError(
            f"Ollama request failed ({type(exc).__name__}); "
            "is `ollama serve` running and model pulled?"
        ) from exc

    d = r.json()
    return {
        "text": d["message"]["content"],
        "prompt_tokens": d.get("prompt_eval_count", 0),
        "completion_tokens": d.get("eval_count", 0),
        "model": model,
        "tokens_estimated": False,
    }

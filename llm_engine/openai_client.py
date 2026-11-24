"""OpenAI chat-completions client (API key only from environment)."""
from __future__ import annotations

import requests

import config


class LLMError(RuntimeError):
    pass


def complete(messages: list[dict], model: str | None = None, timeout: int = 60) -> dict:
    if not config.OPENAI_API_KEY:
        raise LLMError("OPENAI_API_KEY is not set (put it in .env, never in code)")
    model = model or config.OPENAI_MODEL
    try:
        r = requests.post(f"{config.OPENAI_BASE_URL}/chat/completions", timeout=timeout,
                          headers={"Authorization": f"Bearer {config.OPENAI_API_KEY}"},
                          json={"model": model, "messages": messages, "temperature": 0.1, "response_format": {"type": "json_object"}})
        r.raise_for_status()
    except requests.RequestException as exc:
        raise LLMError(f"OpenAI request failed: {type(exc).__name__}") from exc      # message omits headers/keys
    d = r.json()
    u = d.get("usage", {})
    return {"text": d["choices"][0]["message"]["content"], "prompt_tokens": u.get("prompt_tokens", 0),
            "completion_tokens": u.get("completion_tokens", 0), "model": model, "tokens_estimated": False}

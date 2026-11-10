from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any


def llm_configured() -> bool:
    return bool(os.getenv("LLM_API_KEY") and os.getenv("LLM_BASE_URL"))


def analyze_with_llm(hostname: str, title: str, snippets: list[str], local_risk: int) -> dict[str, Any] | None:
    """
    OpenAI-compatible Chat Completions.
    Подходит: OpenAI, DeepSeek, локальный прокси и т.п.
    """
    api_key = os.getenv("LLM_API_KEY")
    base = (os.getenv("LLM_BASE_URL") or "").rstrip("/")
    model = os.getenv("LLM_MODEL", "deepseek-chat")
    if not api_key or not base:
        return None

    text = f"TITLE: {title}\nHOST: {hostname}\nSNIPPETS:\n- " + "\n- ".join(snippets[:30])
    system = (
        "Ты модуль антифишинга. Оцени, является ли страница фишингом/скамом "
        "на основе коротких текстов (заголовки, кнопки). "
        "Ответь СТРОГО JSON: {\"risk\":0-100,\"reasons\":[\"...\"],\"phishing\":true|false}. "
        "Не считай обычный логин фишингом. Ищи давление, панику, фейковые выплаты, "
        "просьбы паролей от чужих сервисов, имитацию брендов."
    )
    user = f"Локальный риск-эвристика: {local_risk}\n\n{text}"

    payload = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "response_format": {"type": "json_object"},
    }

    req = urllib.request.Request(
        f"{base}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return None

    try:
        content = raw["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        risk = int(parsed.get("risk", local_risk))
        reasons = parsed.get("reasons") or []
        if not isinstance(reasons, list):
            reasons = [str(reasons)]
        return {
            "risk": max(0, min(100, risk)),
            "reasons": [str(r) for r in reasons][:8],
            "phishing": bool(parsed.get("phishing", risk >= 70)),
        }
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None

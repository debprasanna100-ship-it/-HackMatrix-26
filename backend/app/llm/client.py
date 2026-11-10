"""Provider-agnostic LLM interface.

One OpenAI-compatible chat-completions implementation covers the major providers
(OpenAI, DeepSeek, Moonshot/Kimi, Z.ai/GLM, OpenRouter, local Ollama/vLLM) by
changing base_url + model via environment variables. When no API key is set the
client reports unavailable and callers must fall back to rule-based behaviour —
the pipeline never fails because a third-party AI service is down.

Security notes:
  * The API key is read from settings (env only) and NEVER logged.
  * Untrusted content (web text, user messages) reaches this layer already
    delimited; prompt-injection defence lives in llm/explain.py.
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from typing import Optional

import httpx

from ..config import Settings

logger = logging.getLogger("trustlens.llm")


@dataclass
class LlmUnavailable(Exception):
    """No key configured, network failure, or provider error."""

    reason: str


class LlmClient:
    def __init__(self, settings: Settings):
        self._settings = settings
        self.available = bool(settings.llm_api_key)
        self.model = settings.llm_model
        self.base_url = settings.llm_base_url.rstrip("/")
        self._timeout = httpx.Timeout(connect=5.0, read=settings.llm_timeout_seconds, write=10.0, pool=5.0)

    async def complete(self, system_prompt: str, user_content: str, max_tokens: int = 900) -> str:
        """Chat completion returning raw assistant text. Raises LlmUnavailable."""
        if not self.available:
            raise LlmUnavailable("no API key configured (TRUSTLENS_LLM_API_KEY)")
        url = f"{self.base_url}/chat/completions"
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.2,
            "max_tokens": max_tokens,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout, trust_env=False) as client:
                resp = await client.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {self._settings.llm_api_key}",
                        "Content-Type": "application/json",
                    },
                    json=payload,
                )
        except (httpx.HTTPError, OSError) as exc:
            # Never include request headers (they carry the key).
            raise LlmUnavailable(f"network error ({type(exc).__name__})") from exc

        if resp.status_code == 429:
            raise LlmUnavailable("provider rate limited (HTTP 429)")
        if resp.status_code >= 400:
            raise LlmUnavailable(f"provider error (HTTP {resp.status_code})")
        try:
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LlmUnavailable(f"unexpected provider response shape ({type(exc).__name__})") from exc
        return str(content)


def extract_json_object(text: str) -> dict:
    """Pull the first JSON object out of an LLM reply (tolerates code fences)."""
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else None
    if candidate is None:
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end > start:
            candidate = text[start : end + 1]
    if candidate is None:
        raise ValueError("no JSON object found in model output")
    parsed = json.loads(candidate)
    if not isinstance(parsed, dict):
        raise ValueError("model output JSON is not an object")
    return parsed

"""OpenAI-compatible chat provider.

Works with the official OpenAI API and any server that speaks the same
``/chat/completions`` protocol (DeepSeek, Qwen/DashScope compatible mode,
vLLM, Ollama, LM Studio, ...).  The SDK is imported lazily so the offline
build does not depend on it being installed.
"""

from __future__ import annotations

import time
from typing import Any

from .base import (
    LLMConfigurationError,
    LLMGenerationError,
    LLMProvider,
    LLMResponse,
)

DEFAULT_MODEL = "gpt-4o-mini"


def _collect_usage(raw_usage: Any) -> dict[str, Any]:
    if raw_usage is None:
        return {}
    if isinstance(raw_usage, dict):
        return dict(raw_usage)
    model_dump = getattr(raw_usage, "model_dump", None)
    if callable(model_dump):
        try:
            data = model_dump()
            if isinstance(data, dict):
                return data
        except Exception:  # noqa: BLE001 - usage is best-effort metadata
            pass
    usage: dict[str, Any] = {}
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = getattr(raw_usage, key, None)
        if isinstance(value, (int, float)):
            usage[key] = value
    return usage


class OpenAICompatProvider(LLMProvider):
    """Chat-completions provider with optional JSON response mode."""

    name = "openai"

    def __init__(
        self,
        api_key: str,
        model: str = "",
        base_url: str = "",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = (api_key or "").strip()
        self.model = (model or "").strip() or DEFAULT_MODEL
        self.base_url = (base_url or "").strip()
        try:
            self.timeout = float(timeout)
        except (TypeError, ValueError):
            self.timeout = 30.0
        if not self.api_key:
            raise LLMConfigurationError("OpenAI 兼容接口缺少 API Key。")

    def generate(
        self,
        system: str,
        prompt: str,
        *,
        json_mode: bool = False,
        temperature: float = 0.1,
        max_tokens: int = 1400,
    ) -> LLMResponse:
        started = time.perf_counter()
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise LLMConfigurationError(
                "未安装 openai SDK，无法调用 OpenAI 兼容接口。"
            ) from exc

        client_kwargs: dict[str, Any] = {
            "api_key": self.api_key,
            "timeout": self.timeout,
        }
        if self.base_url:
            client_kwargs["base_url"] = self.base_url

        request: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": prompt},
            ],
            "temperature": float(temperature),
            "max_tokens": int(max_tokens),
        }
        if json_mode:
            request["response_format"] = {"type": "json_object"}

        try:
            client = OpenAI(**client_kwargs)
            completion = client.chat.completions.create(**request)
        except Exception as exc:  # noqa: BLE001 - normalise vendor errors
            raise LLMGenerationError(
                f"OpenAI 兼容接口调用失败：{type(exc).__name__}: {exc}"
            ) from exc

        choices = getattr(completion, "choices", None) or []
        text = ""
        if choices:
            message = getattr(choices[0], "message", None)
            text = getattr(message, "content", "") or ""

        return LLMResponse(
            text=text,
            provider=self.name,
            model=str(getattr(completion, "model", "") or self.model),
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            usage=_collect_usage(getattr(completion, "usage", None)),
        )
"""Anthropic Messages API provider.

Claude has no ``response_format`` switch, so ``json_mode`` is accepted for
interface compatibility and satisfied by prompt-level instructions written by
the analyst layer.  The SDK import is lazy.
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

DEFAULT_MODEL = "claude-sonnet-5-5"


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
    for key in ("input_tokens", "output_tokens"):
        value = getattr(raw_usage, key, None)
        if isinstance(value, (int, float)):
            usage[key] = value
    return usage


class AnthropicProvider(LLMProvider):
    """Thin wrapper around ``anthropic.Anthropic`` messages."""

    name = "anthropic"

    def __init__(self, api_key: str, model: str = "", timeout: float = 30.0) -> None:
        self.api_key = (api_key or "").strip()
        self.model = (model or "").strip() or DEFAULT_MODEL
        try:
            self.timeout = float(timeout)
        except (TypeError, ValueError):
            self.timeout = 30.0
        if not self.api_key:
            raise LLMConfigurationError("Anthropic 接口缺少 ANTHROPIC_API_KEY。")

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
            from anthropic import Anthropic
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise LLMConfigurationError(
                "未安装 anthropic SDK，无法调用 Claude 接口。"
            ) from exc

        try:
            client = Anthropic(api_key=self.api_key, timeout=self.timeout)
            message = client.messages.create(
                model=self.model,
                system=system,
                messages=[{"role": "user", "content": prompt}],
                temperature=float(temperature),
                max_tokens=int(max_tokens),
            )
        except Exception as exc:  # noqa: BLE001 - normalise vendor errors
            raise LLMGenerationError(
                f"Anthropic 接口调用失败：{type(exc).__name__}: {exc}"
            ) from exc

        blocks = getattr(message, "content", None) or []
        parts: list[str] = []
        for block in blocks:
            if getattr(block, "type", "") == "text":
                text = getattr(block, "text", "")
                if text:
                    parts.append(str(text))

        return LLMResponse(
            text="".join(parts),
            provider=self.name,
            model=str(getattr(message, "model", "") or self.model),
            latency_ms=round((time.perf_counter() - started) * 1000, 2),
            usage=_collect_usage(getattr(message, "usage", None)),
        )
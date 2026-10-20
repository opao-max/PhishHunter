"""Provider/analyst construction with safe, offline-first fallbacks.

``llm_provider`` semantics (see docs/INTERFACES.md section 4):

* ``none``      -> no provider, ``HeuristicAnalyst``
* ``mock``      -> ``MockLLM`` (deterministic, offline)
* ``openai``    -> OpenAI-compatible provider; missing key/SDK -> MockLLM
* ``anthropic`` -> Anthropic provider; missing key/SDK -> MockLLM
* ``auto``      -> Anthropic, then OpenAI-compatible, then MockLLM

Construction never raises and never performs network I/O.  Degradations are
recorded on ``settings.extra["llm_note"]`` (latest) and
``settings.extra["llm_notes"]`` (history) so the CLI/report can surface them.
"""

from __future__ import annotations

import importlib.util
import os
from typing import Any

from ..config import Settings
from .analyst import HeuristicAnalyst, LLMAnalyst
from .anthropic_provider import AnthropicProvider
from .base import LLMProvider
from .mock import MockLLM
from .openai_compat import OpenAICompatProvider

_NONE_ALIASES = {"none", "off", "disabled", "heuristic"}


def _note(settings: Any, message: str) -> None:
    """Record a degradation note without printing or raising."""
    try:
        extra = settings.extra
        previous = str(extra.get("llm_notes", "") or "")
        extra["llm_notes"] = f"{previous}；{message}" if previous else message
        extra["llm_note"] = message
    except Exception:  # noqa: BLE001 - notes must never break construction
        pass


def _sdk_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError):
        return False


def _timeout(settings: Any) -> float:
    try:
        return float(getattr(settings, "llm_timeout_s", 30.0) or 30.0)
    except (TypeError, ValueError):
        return 30.0


def _openai_key(settings: Any) -> str:
    return (
        str(getattr(settings, "llm_api_key", "") or "").strip()
        or os.getenv("PHISHHUNTER_LLM_API_KEY", "").strip()
        or os.getenv("OPENAI_API_KEY", "").strip()
    )


def _anthropic_key() -> str:
    return os.getenv("ANTHROPIC_API_KEY", "").strip()


def _build_openai(settings: Any) -> LLMProvider:
    key = _openai_key(settings)
    if not key:
        _note(settings, "缺少 OpenAI 兼容 API Key，使用离线 MockLLM。")
        return MockLLM()
    if not _sdk_available("openai"):
        _note(settings, "未安装 openai SDK，使用离线 MockLLM。")
        return MockLLM()
    try:
        return OpenAICompatProvider(
            api_key=key,
            model=str(getattr(settings, "llm_model", "") or ""),
            base_url=str(getattr(settings, "llm_base_url", "") or ""),
            timeout=_timeout(settings),
        )
    except Exception as exc:  # noqa: BLE001 - degrade, never raise
        _note(
            settings,
            f"OpenAI 兼容接口初始化失败，使用离线 MockLLM："
            f"{type(exc).__name__}: {exc}",
        )
        return MockLLM()


def _build_anthropic(settings: Any) -> LLMProvider:
    key = _anthropic_key()
    if not key:
        _note(settings, "缺少 ANTHROPIC_API_KEY，使用离线 MockLLM。")
        return MockLLM()
    if not _sdk_available("anthropic"):
        _note(settings, "未安装 anthropic SDK，使用离线 MockLLM。")
        return MockLLM()
    try:
        return AnthropicProvider(
            api_key=key,
            model=str(getattr(settings, "llm_model", "") or ""),
            timeout=_timeout(settings),
        )
    except Exception as exc:  # noqa: BLE001 - degrade, never raise
        _note(
            settings,
            f"Anthropic 接口初始化失败，使用离线 MockLLM："
            f"{type(exc).__name__}: {exc}",
        )
        return MockLLM()


def _build_provider(settings: Any) -> LLMProvider | None:
    requested = str(getattr(settings, "llm_provider", "auto") or "auto").strip().lower()

    if requested in _NONE_ALIASES:
        return None
    if requested == "mock":
        return MockLLM()
    if requested == "openai":
        return _build_openai(settings)
    if requested == "anthropic":
        return _build_anthropic(settings)
    if requested == "auto":
        if _anthropic_key():
            return _build_anthropic(settings)
        if _openai_key(settings):
            return _build_openai(settings)
        _note(settings, "未检测到可用的 LLM API Key，自动降级为离线 MockLLM。")
        return MockLLM()

    _note(settings, f"未知的 LLM provider「{requested}」，使用离线 MockLLM。")
    return MockLLM()


def build_provider(settings: Settings) -> LLMProvider | None:
    """Resolve the configured provider, degrading to MockLLM on any failure."""
    try:
        return _build_provider(settings)
    except Exception as exc:  # noqa: BLE001 - the agent must always start
        _note(
            settings,
            f"LLM provider 初始化异常，使用离线 MockLLM："
            f"{type(exc).__name__}: {exc}",
        )
        return MockLLM()


def build_analyst(settings: Settings, provider: LLMProvider | None) -> object:
    """Return ``LLMAnalyst`` when a provider is active, else the heuristic one."""
    if provider is None or not bool(getattr(settings, "use_llm", True)):
        return HeuristicAnalyst()
    try:
        temperature = float(getattr(settings, "llm_temperature", 0.1) or 0.1)
    except (TypeError, ValueError):
        temperature = 0.1
    try:
        max_tokens = int(getattr(settings, "llm_max_tokens", 1400) or 1400)
    except (TypeError, ValueError):
        max_tokens = 1400
    try:
        return LLMAnalyst(
            provider,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    except Exception as exc:  # noqa: BLE001 - analyst construction fallback
        _note(
            settings,
            f"LLM 分析器初始化失败，使用确定性分析器："
            f"{type(exc).__name__}: {exc}",
        )
        return HeuristicAnalyst()
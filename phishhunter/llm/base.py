"""Provider-agnostic LLM abstraction.

The rest of PhishHunter never talks to a vendor SDK directly.  Providers return
a small, immutable-in-practice ``LLMResponse`` so that latency, usage and the
resolved model name can be surfaced in the audit report without leaking vendor
types into the analyst layer.

No provider performs network I/O at import or construction time.  The optional
SDKs are imported lazily inside ``generate`` so that the offline build works on
a machine with neither ``openai`` nor ``anthropic`` installed.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


class LLMError(RuntimeError):
    """Base class for all LLM-layer failures."""


class LLMConfigurationError(LLMError):
    """The provider is unusable as configured (missing key/SDK/bad params)."""


class LLMGenerationError(LLMError):
    """The remote provider failed while generating a completion."""


@dataclass
class LLMResponse:
    """One completion plus the metadata needed for the audit trail."""

    text: str
    provider: str
    model: str
    latency_ms: float = 0.0
    usage: dict[str, Any] = field(default_factory=dict)


class LLMProvider(ABC):
    """Minimal synchronous chat interface shared by every backend."""

    name: str = "llm"
    model: str = ""

    @abstractmethod
    def generate(
        self,
        system: str,
        prompt: str,
        *,
        json_mode: bool = False,
        temperature: float = 0.1,
        max_tokens: int = 1400,
    ) -> LLMResponse:
        """Generate a completion.

        ``system`` is the trusted instruction channel.  ``prompt`` may contain
        untrusted email content and must stay a separate message so providers
        that support instruction hierarchy can keep the boundary intact.
        """
        raise NotImplementedError
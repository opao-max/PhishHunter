"""Runtime configuration for PhishHunter.

The system is offline-first: every network-capable tool is mocked by default.
Set ``PHISHHUNTER_ALLOW_NETWORK=1`` only after wiring real, safe integrations.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INTEL_PATH = PROJECT_ROOT / "data" / "mock_intel.json"
DEFAULT_EMAIL_DIR = PROJECT_ROOT / "data" / "emails"


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, "").strip())
    except (TypeError, ValueError):
        return default


def internal_domains() -> frozenset[str]:
    """Domains owned by the protected organization (comma-separated env)."""
    raw = os.getenv("PHISHHUNTER_INTERNAL_DOMAINS", "company.com")
    return frozenset(
        part.strip().lower().rstrip(".")
        for part in raw.split(",")
        if part.strip()
    )


@dataclass
class Settings:
    # LLM: auto | none | mock | openai | anthropic
    llm_provider: str = "auto"
    llm_model: str = ""
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_timeout_s: float = 30.0
    llm_temperature: float = 0.1
    llm_max_tokens: int = 1400

    # Agent
    planner: str = "heuristic"  # heuristic | llm
    max_tool_calls: int = 12
    tool_timeout_s: float = 5.0
    max_links_to_inspect: int = 4
    max_attachments_to_inspect: int = 4
    max_images_to_inspect: int = 2
    use_llm: bool = True

    # Scoring thresholds (0-100)
    block_threshold: int = 70
    quarantine_threshold: int = 40
    llm_max_adjustment: float = 8.0

    # Data / safety
    intel_path: str = str(DEFAULT_INTEL_PATH)
    allow_network: bool = False
    mock_intel: bool = True
    analysis_date: str = ""  # optional ISO-8601 override for mock age calculations
    extra: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Settings":
        provider = (
            os.getenv("PHISHHUNTER_LLM_PROVIDER")
            or os.getenv("PHISHHUNTER_LLM")
            or "auto"
        ).strip().lower()
        settings = cls(
            llm_provider=provider,
            llm_model=os.getenv("PHISHHUNTER_LLM_MODEL", "").strip(),
            llm_api_key=(
                os.getenv("PHISHHUNTER_LLM_API_KEY")
                or os.getenv("OPENAI_API_KEY")
                or ""
            ).strip(),
            llm_base_url=(
                os.getenv("PHISHHUNTER_LLM_BASE_URL")
                or os.getenv("OPENAI_BASE_URL")
                or ""
            ).strip(),
            llm_timeout_s=float(os.getenv("PHISHHUNTER_LLM_TIMEOUT", "30") or 30),
            planner=(os.getenv("PHISHHUNTER_PLANNER", "heuristic").strip().lower()),
            max_tool_calls=_env_int("PHISHHUNTER_MAX_TOOL_CALLS", 12),
            block_threshold=_env_int("PHISHHUNTER_BLOCK_THRESHOLD", 70),
            quarantine_threshold=_env_int("PHISHHUNTER_QUARANTINE_THRESHOLD", 40),
            intel_path=os.getenv("PHISHHUNTER_INTEL_PATH", str(DEFAULT_INTEL_PATH)),
            allow_network=_env_bool("PHISHHUNTER_ALLOW_NETWORK", False),
            analysis_date=os.getenv("PHISHHUNTER_ANALYSIS_DATE", "").strip(),
        )
        if os.getenv("PHISHHUNTER_NO_LLM", "").strip() in {"1", "true", "yes"}:
            settings.llm_provider = "none"
        return settings

    def resolved_intel_path(self) -> Path:
        path = Path(self.intel_path)
        if not path.is_absolute():
            path = PROJECT_ROOT / path
        return path

    def threshold_labels(self) -> dict[str, int]:
        return {
            "block": self.block_threshold,
            "quarantine": self.quarantine_threshold,
        }
"""PhishHunter - an evidence-grounded, multi-modal phishing triage agent."""

from __future__ import annotations

__version__ = "1.0.0"

__all__ = [
    "AnalysisReport",
    "EmailMessage",
    "Evidence",
    "PhishHunterAgent",
    "Settings",
]


def __getattr__(name: str):
    # Lazy imports keep subpackages usable in isolation (and speed up tests).
    if name == "PhishHunterAgent":
        from .agent import PhishHunterAgent

        return PhishHunterAgent
    if name == "Settings":
        from .config import Settings

        return Settings
    if name in {"AnalysisReport", "EmailMessage", "Evidence"}:
        from . import models

        return getattr(models, name)
    raise AttributeError(name)
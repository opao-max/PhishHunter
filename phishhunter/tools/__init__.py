"""Tool layer for PhishHunter.

All seven investigation capabilities share one read-only
:class:`~phishhunter.tools.intel.MockIntelProvider` so their view of an IOC is
consistent.  ``build_default_registry`` is the only entry point the agent
needs; individual tool classes remain importable for tests and extensions.
"""

from __future__ import annotations

from pathlib import Path

from .base import BaseTool, ToolRegistry
from .intel import MockIntelProvider, build_provider
from .whois_tool import WhoisLookupTool
from .dns_tool import DnsAuthCheckTool
from .url_tool import UrlReputationTool, UrlSandboxTool
from .file_tool import FileReputationTool
from .image_tool import ImageForensicsTool
from .campaign_tool import RetrieveSimilarCampaignsTool

__all__ = [
    "BaseTool",
    "ToolRegistry",
    "MockIntelProvider",
    "build_provider",
    "build_default_registry",
    "WhoisLookupTool",
    "DnsAuthCheckTool",
    "UrlReputationTool",
    "UrlSandboxTool",
    "FileReputationTool",
    "ImageForensicsTool",
    "RetrieveSimilarCampaignsTool",
]

#: The seven tool names registered by :func:`build_default_registry`.
DEFAULT_TOOL_NAMES = (
    "whois_lookup",
    "dns_auth_check",
    "url_reputation",
    "url_sandbox",
    "file_reputation",
    "image_forensics",
    "retrieve_similar_campaigns",
)


def build_default_registry(
    intel_path: str | Path | None = None,
) -> ToolRegistry:
    """Build the default registry with one shared mock intel provider.

    ``intel_path=None`` resolves to ``data/mock_intel.json`` relative to the
    project root.  A missing or malformed file yields a functional provider
    that reports every IOC as not found.
    """
    provider = MockIntelProvider(intel_path)
    return ToolRegistry(
        [
            WhoisLookupTool(provider),
            DnsAuthCheckTool(provider),
            UrlReputationTool(provider),
            UrlSandboxTool(provider),
            FileReputationTool(provider),
            ImageForensicsTool(),
            RetrieveSimilarCampaignsTool(provider),
        ]
    )
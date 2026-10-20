"""Static (no-IOC-lookup) perception layer.

Each detector is a pure function ``(EmailMessage) -> list[Evidence]``.  The
orchestrator runs every detector and isolates failures so one malformed email
field can never take down the whole triage.

Imports are lazy so a single detector module can be developed and tested in
isolation (useful while the package is being assembled).
"""

from __future__ import annotations

import importlib
from typing import Callable

from ..models import EmailMessage, Evidence

Detector = Callable[[EmailMessage], list[Evidence]]

DETECTORS: list[tuple[str, str, str]] = [
    ("header_analysis", ".header_analysis", "analyze_headers"),
    ("sender_identity", ".sender_identity", "analyze_sender"),
    ("text_analysis", ".text_analysis", "analyze_text"),
    ("link_analysis", ".link_analysis", "analyze_links"),
    ("attachment_analysis", ".attachment_analysis", "analyze_attachments"),
    ("image_analysis", ".image_analysis", "analyze_images"),
    ("injection_guard", ".injection_guard", "scan_injection"),
]


def get_detector(module_suffix: str, function_name: str) -> Detector:
    module = importlib.import_module(module_suffix, package=__name__)
    return getattr(module, function_name)


def run_static_detectors(email: EmailMessage) -> tuple[list[Evidence], list[str]]:
    """Run all static detectors, returning evidence plus non-fatal errors."""
    evidence: list[Evidence] = []
    errors: list[str] = []
    for name, module_suffix, function_name in DETECTORS:
        try:
            detector = get_detector(module_suffix, function_name)
            produced = detector(email) or []
            for item in produced:
                if not item.source:
                    item.source = f"detector:{name}"
                elif not item.source.startswith(("detector:", "tool:")):
                    item.source = f"detector:{item.source}"
            evidence.extend(produced)
        except Exception as exc:  # noqa: BLE001 - isolate detector failures
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
    return evidence, errors
"""Attachment hash reputation tool (offline mock).

The tool never opens an attachment.  It correlates the submitted SHA-256 with
malware intelligence and, when a filename is supplied, checks whether the
declared file type contradicts the observed type.
"""

from __future__ import annotations

import os
from typing import Any

from ..models import (
    POLARITY_MITIGATING,
    Evidence,
    ToolResult,
    make_evidence,
)
from .base import BaseTool
from .intel import MockIntelProvider, normalize_hash, require_text_param

_MALICIOUS_VERDICTS = {"malicious", "infected", "trojan", "malware", "ransomware"}
_SUSPICIOUS_VERDICTS = {
    "suspicious",
    "potentially unwanted",
    "potentially_unwanted",
    "pua",
    "riskware",
}
_CLEAN_VERDICTS = {"clean", "benign", "good", "trusted"}

_EXECUTABLE_TYPES = (
    "pe32",
    "pe32+",
    "elf",
    "mach-o",
    "dll",
    "executable",
    "javascript",
    "powershell",
    "batch",
    "script",
)
_DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".txt",
    ".csv",
    ".rtf",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
}
_EXECUTABLE_EXTENSIONS = {
    ".exe",
    ".scr",
    ".dll",
    ".js",
    ".jse",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".msi",
    ".jar",
    ".com",
    ".pif",
    ".hta",
}


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def type_mismatch(filename: str, file_type: str) -> bool:
    """True when the extension and the observed file type disagree.

    This catches e.g. ``invoice.pdf`` that is actually a PE32 executable.
    Missing information is never treated as a mismatch.
    """
    if not filename or not file_type:
        return False
    extension = os.path.splitext(filename.lower())[1]
    observed = file_type.strip().lower()
    if not extension or not observed:
        return False
    looks_executable = any(token in observed for token in _EXECUTABLE_TYPES)
    looks_document = any(
        token in observed for token in ("pdf", "document", "image", "text", "office")
    )
    if extension in _DOCUMENT_EXTENSIONS and looks_executable:
        return True
    if extension in _EXECUTABLE_EXTENSIONS and looks_document:
        return True
    return False


class FileReputationTool(BaseTool):
    name = "file_reputation"
    description = "通过 SHA-256 查询附件的恶意软件情报与真实文件类型（离线 Mock）。"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "sha256": {
                "type": "string",
                "description": "附件 SHA-256（可带 sha256: 前缀）",
                "minLength": 1,
            },
            "filename": {
                "type": "string",
                "description": "附件原始文件名，用于识别类型伪装",
            },
        },
        "required": ["sha256"],
        "additionalProperties": False,
    }

    def __init__(self, provider: MockIntelProvider) -> None:
        self.provider = provider

    def run(self, params: dict[str, Any]) -> ToolResult:
        sha256 = normalize_hash(require_text_param(params, "sha256", self.name))
        if not sha256:
            raise ValueError(f"{self.name}: parameter 'sha256' is empty")
        filename = params.get("filename")
        filename = filename.strip() if isinstance(filename, str) else ""

        data = self.provider.file_reputation(sha256)
        evidence: list[Evidence] = []
        if data.get("found"):
            evidence = self._analyze(sha256, filename, data)
        return ToolResult(tool=self.name, ok=True, data=data, evidence=evidence)

    def _analyze(
        self, sha256: str, filename: str, data: dict[str, Any]
    ) -> list[Evidence]:
        verdict = str(data.get("verdict") or "").strip().lower()
        vt_malicious = _as_int(data.get("vt_malicious"))
        family = str(data.get("malware_family") or "").strip()
        file_type = str(data.get("file_type") or "").strip()
        names = _string_list(data.get("names"))

        malicious = verdict in _MALICIOUS_VERDICTS or (
            vt_malicious is not None and vt_malicious >= 5
        )
        if malicious:
            detail_parts = []
            if family:
                detail_parts.append(f"家族 {family}")
            if vt_malicious is not None:
                detail_parts.append(f"{vt_malicious} 个引擎判定恶意")
            if file_type:
                detail_parts.append(f"文件类型 {file_type}")
            if names:
                detail_parts.append(f"已知文件名 {'、'.join(names[:3])}")
            return [
                make_evidence(
                    "attachment",
                    "附件哈希被确认为恶意",
                    f"附件 {filename or sha256} 命中恶意情报"
                    + ("：" + "；".join(detail_parts) if detail_parts else "。"),
                    0.96,
                    0.98,
                    source=f"tool:{self.name}",
                    tags=["known_malicious_file"],
                    raw={
                        "sha256": sha256,
                        "filename": filename,
                        "malware_family": family,
                        "vt_malicious": vt_malicious,
                    },
                )
            ]

        mismatch = type_mismatch(filename, file_type)
        suspicious = verdict in _SUSPICIOUS_VERDICTS
        if suspicious or mismatch:
            issues: list[str] = []
            if suspicious:
                issues.append(f"情报判定为 {verdict or '可疑'}")
            if mismatch:
                issues.append(
                    f"文件名声明为 {os.path.splitext(filename)[1] or '未知扩展名'}"
                    f"，实际类型为 {file_type}"
                )
            return [
                make_evidence(
                    "attachment",
                    "附件类型或信誉可疑",
                    f"附件 {filename or sha256}：" + "；".join(issues) + "。",
                    0.6,
                    0.8,
                    source=f"tool:{self.name}",
                    tags=(
                        ["suspicious_file"]
                        if suspicious
                        else ["file_type_mismatch"]
                    ),
                    raw={
                        "sha256": sha256,
                        "filename": filename,
                        "verdict": verdict,
                        "file_type": file_type,
                    },
                )
            ]

        known_good = verdict in _CLEAN_VERDICTS and (
            bool(names) or (vt_malicious is not None and vt_malicious == 0)
        )
        if known_good:
            return [
                make_evidence(
                    "attachment",
                    "附件哈希信誉良好",
                    f"附件 {filename or sha256} 未命中恶意情报"
                    + (f"，文件类型为 {file_type}" if file_type else "")
                    + "。",
                    0.35,
                    0.8,
                    source=f"tool:{self.name}",
                    tags=["clean_file"],
                    raw={"sha256": sha256, "filename": filename},
                    polarity=POLARITY_MITIGATING,
                )
            ]
        return []
"""URL reputation and sandbox tools (offline mock).

Both tools operate on data returned by :class:`MockIntelProvider`; they never
fetch the URL themselves.  Evidence is tiered so that the strongest, most
specific finding is reported once rather than duplicating the same signal.
"""

from __future__ import annotations

from typing import Any

from ..models import (
    POLARITY_MITIGATING,
    Evidence,
    ToolResult,
    make_evidence,
)
from .base import BaseTool
from .intel import (
    MockIntelProvider,
    is_ip_literal,
    normalize_url,
    require_text_param,
    url_host,
)

_MALICIOUS_CATEGORIES = {
    "phishing",
    "malware",
    "malicious",
    "credential-harvesting",
    "credential harvesting",
    "spam",
    "scam",
    "fraud",
}


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _categories(data: dict[str, Any]) -> list[str]:
    raw = data.get("categories")
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        raw = []
    values = [str(item).strip().lower() for item in raw if str(item).strip()]
    category = str(data.get("category") or "").strip().lower()
    if category and category not in values:
        values.append(category)
    return values


def _is_suspicious_category(categories: list[str]) -> bool:
    return any(
        item in _MALICIOUS_CATEGORIES
        or item.replace("_", "-") in _MALICIOUS_CATEGORIES
        for item in categories
    )


def _normalized_compare(left: str, right: str) -> bool:
    return normalize_url(left) == normalize_url(right)


class UrlReputationTool(BaseTool):
    name = "url_reputation"
    description = "查询 URL 的多引擎信誉、安全浏览判定、分类与首次发现时间（离线 Mock）。"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "要查询信誉的完整 URL（支持短链接）",
                "minLength": 1,
            }
        },
        "required": ["url"],
        "additionalProperties": False,
    }

    def __init__(self, provider: MockIntelProvider) -> None:
        self.provider = provider

    def run(self, params: dict[str, Any]) -> ToolResult:
        url = require_text_param(params, "url", self.name)
        data = self.provider.url_reputation(url)
        evidence: list[Evidence] = []
        if data.get("found"):
            evidence = self._analyze(url, data)
        return ToolResult(tool=self.name, ok=True, data=data, evidence=evidence)

    def _analyze(self, url: str, data: dict[str, Any]) -> list[Evidence]:
        vt_malicious = _as_int(data.get("vt_malicious"))
        safebrowsing = str(data.get("safebrowsing") or "").strip().lower()
        categories = _categories(data)
        cats_text = "、".join(categories) if categories else "未知"
        safe_browsing_bad = safebrowsing in {
            "malicious",
            "phishing",
            "malware",
            "unwanted",
        }

        if (vt_malicious is not None and vt_malicious >= 5) or safe_browsing_bad:
            engines = (
                f"{vt_malicious} 个引擎判定恶意"
                if vt_malicious is not None
                else "恶意判定"
            )
            return [
                make_evidence(
                    "url",
                    "已知恶意 URL",
                    f"URL {url} 威胁情报：{engines}，"
                    f"Safe Browsing={safebrowsing or '未知'}，分类：{cats_text}。",
                    0.95,
                    0.95,
                    source=f"tool:{self.name}",
                    tags=["known_malicious_url"],
                    raw={
                        "url": url,
                        "vt_malicious": vt_malicious,
                        "safebrowsing": safebrowsing,
                        "categories": categories,
                    },
                )
            ]

        if vt_malicious is not None and 1 <= vt_malicious <= 4:
            return [
                make_evidence(
                    "url",
                    "URL 被少量引擎标记为可疑",
                    f"URL {url} 有 {vt_malicious} 个引擎判定恶意，"
                    f"分类：{cats_text}，需要结合其他证据判断。",
                    0.65,
                    0.8,
                    source=f"tool:{self.name}",
                    tags=["suspicious_url"],
                    raw={"url": url, "vt_malicious": vt_malicious},
                )
            ]

        if _is_suspicious_category(categories):
            return [
                make_evidence(
                    "url",
                    "URL 被归类为可疑类别",
                    f"URL {url} 的信誉分类为 {cats_text}，"
                    "即使当前引擎命中数不高也需要警惕。",
                    0.7,
                    0.8,
                    source=f"tool:{self.name}",
                    tags=["suspicious_category"],
                    raw={"url": url, "categories": categories},
                )
            ]

        first_seen = _as_float(data.get("first_seen_days"))
        if (
            vt_malicious == 0
            and not safe_browsing_bad
            and first_seen is not None
            and first_seen > 365
        ):
            return [
                make_evidence(
                    "url",
                    "URL 信誉记录良好",
                    f"URL {url} 未被引擎判定为恶意，且已存在约 "
                    f"{first_seen / 365:.1f} 年，可作为降低风险的佐证。",
                    0.35,
                    0.8,
                    source=f"tool:{self.name}",
                    tags=["clean_url"],
                    raw={"url": url, "first_seen_days": first_seen},
                    polarity=POLARITY_MITIGATING,
                )
            ]
        return []


class UrlSandboxTool(BaseTool):
    name = "url_sandbox"
    description = "在隔离沙箱中观察 URL 的最终落地页、跳转链、登录表单与下载行为（离线 Mock）。"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "要在沙箱中打开的完整 URL",
                "minLength": 1,
            }
        },
        "required": ["url"],
        "additionalProperties": False,
    }

    def __init__(self, provider: MockIntelProvider) -> None:
        self.provider = provider

    def run(self, params: dict[str, Any]) -> ToolResult:
        url = require_text_param(params, "url", self.name)
        data = self.provider.sandbox(url)
        evidence: list[Evidence] = []
        if data.get("found"):
            evidence = self._analyze(url, data)
        return ToolResult(tool=self.name, ok=True, data=data, evidence=evidence)

    def _analyze(self, url: str, data: dict[str, Any]) -> list[Evidence]:
        evidence: list[Evidence] = []
        redirected_to = str(data.get("final_url") or "").strip()
        raw_redirects = data.get("redirects")
        redirects = (
            [str(item).strip() for item in raw_redirects if str(item).strip()]
            if isinstance(raw_redirects, list)
            else []
        )
        verdict = str(data.get("verdict") or "").strip().lower()
        has_form = bool(data.get("has_password_form"))
        requests_credentials = bool(data.get("requests_credentials"))
        downloads = data.get("downloads")
        downloads = downloads if isinstance(downloads, list) else []

        if has_form or requests_credentials or verdict == "credential_harvest":
            signals: list[str] = []
            if has_form:
                signals.append("存在密码输入表单")
            if requests_credentials:
                signals.append("页面请求提交凭据")
            if verdict == "credential_harvest":
                signals.append("沙箱判定为凭据窃取")
            evidence.append(
                make_evidence(
                    "url",
                    "沙箱发现凭据窃取页面",
                    f"沙箱访问 {url} 后发现：" + "；".join(signals or ["凭据窃取行为"])
                    + "。",
                    0.95,
                    0.95,
                    source=f"tool:{self.name}",
                    tags=["credential_harvest"],
                    raw={"url": url, "verdict": verdict, "final_url": redirected_to},
                )
            )

        landing = redirected_to or (redirects[-1] if redirects else "")
        landing_host = url_host(landing)
        was_redirected = bool(redirects) or (
            bool(redirected_to) and not _normalized_compare(redirected_to, url)
        )
        if landing_host and is_ip_literal(landing_host) and was_redirected:
            chain = " -> ".join(redirects) if redirects else f"{url} -> {landing}"
            evidence.append(
                make_evidence(
                    "url",
                    "链接跳转至 IP 地址",
                    f"沙箱观察到跳转链 {chain}，最终落地到 IP 主机 "
                    f"{landing_host}，绕过域名信誉检查。",
                    0.8,
                    0.9,
                    source=f"tool:{self.name}",
                    tags=["redirect_ip"],
                    raw={
                        "url": url,
                        "final_url": redirected_to,
                        "redirects": redirects,
                    },
                )
            )

        if downloads:
            names = [str(item) for item in downloads][:5]
            evidence.append(
                make_evidence(
                    "url",
                    "沙箱观察到文件下载",
                    f"沙箱访问 {url} 时触发文件下载：{'、'.join(names)}。",
                    0.75,
                    0.85,
                    source=f"tool:{self.name}",
                    tags=["download"],
                    raw={"url": url, "downloads": names},
                )
            )

        if verdict == "clean" and not evidence:
            evidence.append(
                make_evidence(
                    "url",
                    "沙箱未观察到恶意行为",
                    f"沙箱访问 {url} 未发现登录表单、凭据请求或下载行为。",
                    0.25,
                    0.5,
                    source=f"tool:{self.name}",
                    tags=["sandbox_clean"],
                    raw={"url": url},
                    polarity=POLARITY_MITIGATING,
                )
            )
        return evidence
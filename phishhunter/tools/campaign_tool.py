"""Historical campaign retrieval tool (offline, explainable similarity)."""

from __future__ import annotations

from typing import Any

from ..models import Evidence, ToolResult, make_evidence
from .base import BaseTool
from .intel import MockIntelProvider, require_text_param


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class RetrieveSimilarCampaignsTool(BaseTool):
    name = "retrieve_similar_campaigns"
    description = (
        "基于关键词与域名重合度检索历史钓鱼活动库，返回可解释的相似度（离线 Mock）。"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "text": {
                "type": "string",
                "description": "用于匹配的邮件正文或主题文本",
                "minLength": 1,
            },
            "domains": {
                "type": "array",
                "description": "发件域与链接域列表，用于加权匹配",
                "items": {"type": "string"},
            },
        },
        "required": ["text"],
        "additionalProperties": False,
    }

    def __init__(self, provider: MockIntelProvider) -> None:
        self.provider = provider

    def run(self, params: dict[str, Any]) -> ToolResult:
        text = require_text_param(params, "text", self.name)
        raw_domains = params.get("domains")
        if raw_domains is None:
            domains: list[str] = []
        elif isinstance(raw_domains, str):
            domains = [raw_domains]
        elif isinstance(raw_domains, list):
            domains = [str(item) for item in raw_domains if str(item).strip()]
        else:
            raise ValueError(
                f"{self.name}: parameter 'domains' must be a list of strings"
            )

        matches = self.provider.similar_campaigns(text, domains, limit=3)
        evidence: list[Evidence] = []
        if matches:
            best_similarity = _as_float(matches[0].get("similarity")) or 0.0
            # Below 0.3 the overlap is noise (shared words like "invoice");
            # reporting it would inflate threat-intel risk with a phantom hit.
            if best_similarity >= 0.3:
                evidence = [self._analyze(matches[0])]
        data = {"found": bool(matches), "matches": matches}
        return ToolResult(tool=self.name, ok=True, data=data, evidence=evidence)

    def _analyze(self, best: dict[str, Any]) -> Evidence:
        similarity = _as_float(best.get("similarity")) or 0.0
        name = str(best.get("name") or "未命名活动")
        campaign_id = str(best.get("id") or "")
        summary = str(best.get("summary") or "")
        keywords = best.get("matched_keywords")
        keyword_text = (
            "、".join(str(item) for item in keywords)
            if isinstance(keywords, list) and keywords
            else "无"
        )
        if similarity >= 0.5:
            severity, confidence = 0.8, 0.85
        elif similarity >= 0.3:
            severity, confidence = 0.55, 0.8
        else:  # defensive: callers should already filter below 0.3
            severity, confidence = 0.0, 0.0
        detail = (
            f"与历史活动「{name}」"
            + (f"（{campaign_id}）" if campaign_id else "")
            + f" 的相似度为 {similarity:.0%}，命中关键词：{keyword_text}。"
            + (f"活动摘要：{summary}" if summary else "")
        )
        return make_evidence(
            "threat_intel",
            "命中相似历史钓鱼活动",
            detail,
            severity,
            confidence,
            source=f"tool:{self.name}",
            tags=["campaign_match"],
            raw={
                "campaign_id": campaign_id,
                "name": name,
                "similarity": similarity,
            },
        )
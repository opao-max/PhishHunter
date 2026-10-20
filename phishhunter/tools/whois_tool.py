"""WHOIS registration-age tool (offline mock).

Registration age is one of the strongest deterministic phishing signals:
attackers rarely invest in aged infrastructure.  The tool turns the provider
record into evidence and never guesses when a field is absent.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import (
    POLARITY_MITIGATING,
    Evidence,
    ToolResult,
    make_evidence,
)
from .base import BaseTool
from .intel import MockIntelProvider, normalize_domain, require_text_param

_MALICIOUS_CATEGORIES = {
    "phishing",
    "malware",
    "malicious",
    "spam",
    "scam",
    "fraud",
    "credential-harvesting",
}


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(value or "").lower())


def brand_mismatch(domain: str, brand: str) -> bool:
    """True when a claimed brand is not represented by the domain itself.

    ``company.com`` claiming ``company`` is consistent; a domain such as
    ``micr0soft-security.com`` claiming ``microsoft`` is not.  This is a
    deterministic string check, not a WHOIS lookup.
    """
    brand_key = _compact(brand)
    if not brand_key:
        return False
    labels = [_compact(label) for label in normalize_domain(domain).split(".")]
    labels = [label for label in labels if label]
    if not labels:
        return False
    return not any(
        brand_key in label or label in brand_key for label in labels
    )


class WhoisLookupTool(BaseTool):
    name = "whois_lookup"
    description = (
        "查询域名的注册时间、注册商、隐私保护与威胁情报标记（离线 Mock）。"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "要核实的域名，例如 example.com",
                "minLength": 1,
            }
        },
        "required": ["domain"],
        "additionalProperties": False,
    }

    def __init__(self, provider: MockIntelProvider) -> None:
        self.provider = provider

    def run(self, params: dict[str, Any]) -> ToolResult:
        domain = normalize_domain(require_text_param(params, "domain", self.name))
        if not domain:
            raise ValueError(f"{self.name}: parameter 'domain' is not a valid domain")

        data = self.provider.whois(domain)
        evidence: list[Evidence] = []
        if data.get("found"):
            evidence.extend(self._analyze(domain, data))
        return ToolResult(tool=self.name, ok=True, data=data, evidence=evidence)

    # ------------------------------------------------------------------ #

    def _analyze(self, domain: str, data: dict[str, Any]) -> list[Evidence]:
        evidence: list[Evidence] = []
        age = _as_float(data.get("age_days"))
        vt_malicious = _as_int(data.get("vt_malicious"))
        category = str(data.get("category") or "").strip().lower()
        malicious = (vt_malicious is not None and vt_malicious >= 3) or (
            category in _MALICIOUS_CATEGORIES
        )

        if age is not None:
            if age <= 1:
                evidence.append(
                    make_evidence(
                        "threat_intel",
                        "新注册域名",
                        f"域名 {domain} 注册仅 {age:g} 天，属于典型的钓鱼基础设施特征。",
                        0.95,
                        0.95,
                        source=f"tool:{self.name}",
                        tags=["domain_new"],
                        raw={"domain": domain, "age_days": age},
                    )
                )
            elif age <= 7:
                evidence.append(
                    make_evidence(
                        "threat_intel",
                        "新注册域名",
                        f"域名 {domain} 注册仅 {age:g} 天，短期内新建域名常被用于钓鱼。",
                        0.7,
                        0.9,
                        source=f"tool:{self.name}",
                        tags=["domain_new"],
                        raw={"domain": domain, "age_days": age},
                    )
                )
            elif age <= 30:
                evidence.append(
                    make_evidence(
                        "threat_intel",
                        "域名注册时间很短",
                        f"域名 {domain} 注册约 {age:g} 天，尚未建立可信历史。",
                        0.5,
                        0.8,
                        source=f"tool:{self.name}",
                        tags=["recent_domain"],
                        raw={"domain": domain, "age_days": age},
                    )
                )

        if vt_malicious is not None and vt_malicious >= 3:
            evidence.append(
                make_evidence(
                    "threat_intel",
                    "域名被威胁情报标记为恶意",
                    f"域名 {domain} 被 {vt_malicious} 个引擎判定为恶意"
                    + (f"，分类为 {category}。" if category else "。"),
                    0.85,
                    0.9,
                    source=f"tool:{self.name}",
                    tags=["malicious_domain"],
                    raw={"domain": domain, "vt_malicious": vt_malicious},
                )
            )

        brand = str(data.get("brand") or "").strip()
        if brand and brand_mismatch(domain, brand):
            evidence.append(
                make_evidence(
                    "sender_identity",
                    "域名与声称的品牌归属不一致",
                    f"情报显示该域名声称归属「{brand}」，但域名 {domain} "
                    "并非该品牌的官方域名，存在品牌仿冒风险。",
                    0.7,
                    0.8,
                    source=f"tool:{self.name}",
                    tags=["brand_spoof"],
                    raw={"domain": domain, "brand": brand},
                )
            )

        if (
            age is not None
            and age >= 365
            and not malicious
            and (vt_malicious is None or vt_malicious == 0)
        ):
            evidence.append(
                make_evidence(
                    "threat_intel",
                    "域名注册时间较长",
                    f"域名 {domain} 已注册约 {age / 365:.1f} 年，未见恶意情报记录，"
                    "可作为降低风险的佐证。",
                    0.45,
                    0.8,
                    source=f"tool:{self.name}",
                    tags=["established_domain"],
                    raw={"domain": domain, "age_days": age},
                    polarity=POLARITY_MITIGATING,
                )
            )
        return evidence
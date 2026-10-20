"""Published SPF/DKIM/DMARC policy check (offline mock).

This tool answers one question only: *does the sender domain publish a sane
authentication policy?*  Whether the individual message actually passed SPF is
decided by the header detector, so the tool intentionally does not emit
``auth_fail``.
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

FREE_MAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "yahoo.com.cn",
    "icloud.com",
    "me.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "mail.ru",
    "yandex.com",
    "qq.com",
    "foxmail.com",
    "163.com",
    "126.com",
    "sina.com",
    "sohu.com",
    "aliyun.com",
}

_DMARC_POLICY_RE = re.compile(
    r"\bp\s*=\s*(none|quarantine|reject)\b", re.IGNORECASE
)
_SOFT_FAIL_RE = re.compile(r"[~?]all\b", re.IGNORECASE)
_HARD_FAIL_RE = re.compile(r"-all\b", re.IGNORECASE)


def is_free_mail(domain: str) -> bool:
    domain = normalize_domain(domain)
    return domain in FREE_MAIL_DOMAINS or any(
        domain.endswith("." + free) for free in FREE_MAIL_DOMAINS
    )


def dmarc_policy_of(dmarc: str) -> str:
    match = _DMARC_POLICY_RE.search(dmarc or "")
    return match.group(1).lower() if match else ""


class DnsAuthCheckTool(BaseTool):
    name = "dns_auth_check"
    description = "检查域名已发布的 SPF/DKIM/DMARC 邮件认证策略（离线 Mock）。"
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "domain": {
                "type": "string",
                "description": "要检查邮件认证策略的域名，例如 example.com",
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

        data = self.provider.dns(domain)
        evidence: list[Evidence] = []
        if data.get("found"):
            data = self._complete_data(data)
            evidence = self._analyze(domain, data)
        return ToolResult(tool=self.name, ok=True, data=data, evidence=evidence)

    # ------------------------------------------------------------------ #

    @staticmethod
    def _complete_data(data: dict[str, Any]) -> dict[str, Any]:
        """Derive the DMARC policy from the raw record when not provided."""
        result = dict(data)
        if not result.get("dmarc_policy"):
            result["dmarc_policy"] = dmarc_policy_of(str(result.get("dmarc") or ""))
        return result

    def _analyze(self, domain: str, data: dict[str, Any]) -> list[Evidence]:
        # Free-mail providers publish their own policy; a missing record there
        # says nothing about this sender, so stay silent instead of guessing.
        if is_free_mail(domain):
            return []

        spf = str(data.get("spf") or "").strip()
        spf_lower = spf.lower()
        explicit_spf_valid = data.get("spf_valid")
        spf_missing = (
            not spf
            or spf_lower in {"none", "-", "null"}
            or explicit_spf_valid is False
        )
        spf_soft = bool(spf) and bool(_SOFT_FAIL_RE.search(spf))
        spf_hard_fail = bool(spf) and bool(_HARD_FAIL_RE.search(spf))

        dmarc = str(data.get("dmarc") or "").strip()
        policy = str(data.get("dmarc_policy") or dmarc_policy_of(dmarc)).lower()
        dmarc_missing = not dmarc or dmarc.lower() in {"none", "-", "null"}
        dkim = str(data.get("dkim") or "").strip()
        dkim_missing = not dkim or dkim.lower() in {"none", "-", "null"}

        issues: list[str] = []
        tags: list[str] = []
        if spf_missing:
            issues.append("SPF 记录缺失或无效，无法约束发件服务器")
            tags.append("missing_spf")
        elif spf_soft:
            issues.append("SPF 使用软失败（~all），伪造邮件不会被直接拒绝")
            tags.append("soft_spf")
        if dmarc_missing:
            issues.append("DMARC 记录缺失，缺少域名级对齐与处置策略")
            tags.append("missing_dmarc")

        if issues:
            return [
                make_evidence(
                    "header_auth",
                    "域名认证策略缺失或过弱",
                    f"域名 {domain}：" + "；".join(issues) + "。",
                    0.55,
                    0.85,
                    source=f"tool:{self.name}",
                    tags=tags or ["dns_misconfiguration"],
                    raw={
                        "domain": domain,
                        "spf": spf,
                        "dmarc": dmarc,
                        "dmarc_policy": policy,
                    },
                )
            ]

        valid_spf = (
            explicit_spf_valid is True
            or (explicit_spf_valid is None and spf_hard_fail)
        )
        enforcing_dmarc = policy in {"quarantine", "reject"}
        if valid_spf and enforcing_dmarc and not dkim_missing:
            return [
                make_evidence(
                    "header_auth",
                    "域名邮件认证策略配置完善",
                    f"域名 {domain} 已发布有效 SPF 与 DMARC（p={policy}）记录，"
                    "并配置了 DKIM。",
                    0.3,
                    0.75,
                    source=f"tool:{self.name}",
                    tags=["auth_policy_ok"],
                    raw={
                        "domain": domain,
                        "spf": spf,
                        "dmarc": dmarc,
                        "dmarc_policy": policy,
                    },
                    polarity=POLARITY_MITIGATING,
                )
            ]
        return []
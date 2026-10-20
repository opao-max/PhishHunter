"""Header authentication and routing analysis.

This detector normalizes SPF/DKIM/DMARC results from either the explicit
``*_result`` headers or an ``Authentication-Results`` header, and flags the
routing anomalies that static rule engines tend to miss: Reply-To /
Return-Path divergence, display-name / address mismatches and malformed or
missing ``From`` headers.

It is deliberately *not* the place for brand logic (``sender_identity`` owns
that) or for network lookups (the tool layer owns those).
"""

from __future__ import annotations

import re
from email.utils import parseaddr
from typing import Any

from ..models import EmailMessage, Evidence, make_evidence

SOURCE = "header_analysis"

# Canonical authentication outcomes.  Anything else is reported as
# ``unknown`` so a typo cannot silently become a pass.
_RESULT_ALIASES: dict[str, str] = {
    "pass": "pass",
    "passed": "pass",
    "bestguesspass": "pass",
    "fail": "fail",
    "failed": "fail",
    "softfail": "softfail",
    "neutral": "neutral",
    "none": "none",
    "permerror": "permerror",
    "temperror": "temperror",
    "policy": "policy",
    "skipped": "none",
    "": "none",
}

_FAILURE_VALUES = {"fail", "softfail", "permerror"}

_MALFORMED_ADDRESS_RE = re.compile(r"\s")


def _normalize_result(value: str) -> str:
    """Normalize a raw SPF/DKIM/DMARC value to a canonical token."""
    token = (value or "").strip().strip("\"'").lower()
    if not token:
        return "none"
    # Authentication-Results can carry a reason: ``fail (bad signature)``.
    token = re.split(r"[;\s()]", token, maxsplit=1)[0]
    return _RESULT_ALIASES.get(token, token if token in _RESULT_ALIASES.values() else "unknown")


def _result_details(email: EmailMessage) -> dict[str, dict[str, str]]:
    """Collect canonical result, raw header value and provenance per mechanism."""
    auth_header = email.header("authentication-results")
    details: dict[str, dict[str, str]] = {}
    for mechanism in ("spf", "dkim", "dmarc"):
        explicit = email.header(f"{mechanism}_result")
        if explicit:
            raw, origin = explicit, "header"
        elif auth_header:
            raw, origin = auth_header, "authentication-results"
        else:
            raw, origin = "", "missing"
        details[mechanism] = {
            "value": _normalize_result(email.auth_result(mechanism)),
            "raw": raw,
            "origin": origin,
        }
    return details


def _auth_evidence(details: dict[str, dict[str, str]]) -> Evidence | None:
    """Emit at most one aggregated authentication-failure evidence item.

    Meaningful combinations follow the contract:
    - SPF fail / softfail / permerror;
    - DMARC fail;
    - DKIM failure only when SPF did not pass (a broken signature behind an
      authenticated envelope is usually legitimate forwarding).
    A lone ``DMARC=none`` (or a lone ``DKIM=none``) is not evidence of attack.
    """
    spf = details["spf"]["value"]
    dkim = details["dkim"]["value"]
    dmarc = details["dmarc"]["value"]

    spf_bad = spf in _FAILURE_VALUES
    dkim_bad = dkim in {"fail", "permerror"}
    dmarc_bad = dmarc in {"fail", "permerror"}

    if not (spf_bad or dmarc_bad or (dkim_bad and spf != "pass")):
        return None

    if spf == "fail":
        severity = 0.80 if dkim in {"none", "unknown", ""} or dmarc_bad else 0.72
    elif spf == "softfail":
        severity = 0.55
    elif spf == "permerror":
        severity = 0.60
    elif dmarc_bad:
        severity = 0.65
    else:  # DKIM failed while SPF did not pass.
        severity = 0.42
    if spf_bad and dmarc_bad:
        severity = min(0.85, severity + 0.05)

    origins = {item["origin"] for item in details.values()}
    confidence = 0.90 if "header" in origins else 0.78

    tags = ["auth_fail"]
    if spf_bad:
        tags.append("spf_fail")
    if dmarc_bad:
        tags.append("dmarc_fail")

    detail = (
        f"SPF={spf}、DKIM={dkim}、DMARC={dmarc}。"
        "发件域未能提供完整可信的邮件身份认证链，存在伪造发件人的可能。"
    )
    raw: dict[str, Any] = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "spf_raw": details["spf"]["raw"],
        "dkim_raw": details["dkim"]["raw"],
        "dmarc_raw": details["dmarc"]["raw"],
        "spf_origin": details["spf"]["origin"],
        "dkim_origin": details["dkim"]["origin"],
        "dmarc_origin": details["dmarc"]["origin"],
    }
    return make_evidence(
        "header_auth",
        "邮件身份认证失败",
        detail,
        severity,
        confidence=confidence,
        source=SOURCE,
        tags=tags,
        raw=raw,
    )




def _same_organization(left: str, right: str) -> bool:
    """Cheap registrable-domain heuristic for ``mail.company.com`` vs ``company.com``.

    A full public-suffix list is intentionally avoided (no third-party data
    files); the subdomain relation covers the common legitimate cases
    (ticketing, ESP subdomains) without weakening the true mismatch signal.
    """
    if not left or not right:
        return False
    left, right = left.strip(".").lower(), right.strip(".").lower()
    return (
        left == right
        or left.endswith("." + right)
        or right.endswith("." + left)
    )


def _reply_to_evidence(email: EmailMessage) -> Evidence | None:
    """Flag Reply-To divergence, a classic BEC / mailing-list abuse pattern."""
    from_domain = email.from_domain
    reply_domain = email.reply_to_domain
    if not from_domain or not reply_domain or _same_organization(from_domain, reply_domain):
        return None

    free_mail_reply = reply_domain in {
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com",
        "qq.com",
        "163.com",
        "126.com",
    }
    severity = 0.65 if free_mail_reply else 0.58
    detail = (
        f"From 域为 {from_domain}，但 Reply-To 指向 {reply_domain}。"
        "回复将离开原始组织域，常见于 BEC 与凭据回收攻击。"
    )
    return make_evidence(
        "header_auth",
        "Reply-To 与 From 域名不一致",
        detail,
        severity,
        confidence=0.85,
        source=SOURCE,
        tags=["reply_to_mismatch"],
        raw={
            "from_domain": from_domain,
            "reply_to": email.reply_to_address,
            "reply_to_domain": reply_domain,
        },
    )


def _return_path_evidence(email: EmailMessage) -> Evidence | None:
    """Flag envelope/header divergence.

    Legitimate ESPs do this for bounce handling, so severity stays low; it is
    useful as a corroborating signal, never as a standalone accusation.
    """
    from_domain = email.from_domain
    return_domain = ""
    _, address = parseaddr(email.return_path)
    if "@" in address:
        return_domain = address.rsplit("@", 1)[-1].strip().lower().rstrip(".")
    if not from_domain or not return_domain or _same_organization(from_domain, return_domain):
        return None
    detail = (
        f"Return-Path 域为 {return_domain}，与 From 域 {from_domain} 不一致。"
        "邮件转发/代发服务也可能造成此现象，需结合其他证据判断。"
    )
    return make_evidence(
        "header_auth",
        "Return-Path 与 From 域名不一致",
        detail,
        0.35,
        confidence=0.70,
        source=SOURCE,
        tags=["return_path_mismatch"],
        raw={
            "from_domain": from_domain,
            "return_path": email.return_path,
            "return_path_domain": return_domain,
        },
    )


def _display_mismatch_evidence(email: EmailMessage) -> Evidence | None:
    """Detect a display name that embeds a different email address.

    Brand-name impersonation is intentionally left to ``sender_identity``;
    this only covers the syntactic case ``"ceo@bank.com" <ceo@evil.example>``.
    """
    display = email.from_display
    if "@" not in display:
        return None
    _, display_address = parseaddr(display)
    display_address = display_address.strip().lower()
    if not display_address or display_address == email.from_address:
        return None
    detail = (
        f"显示名中包含地址 {display_address}，但实际发件地址为 "
        f"{email.from_address}。显示身份与实际路由身份不一致。"
    )
    return make_evidence(
        "header_auth",
        "显示名与实际发件地址不一致",
        detail,
        0.60,
        confidence=0.85,
        source=SOURCE,
        tags=["display_mismatch"],
        raw={
            "from_display": display,
            "display_address": display_address,
            "from_address": email.from_address,
        },
    )


def _malformed_from_evidence(email: EmailMessage) -> Evidence | None:
    """Flag an absent or syntactically broken From header."""
    raw_from = email.sender_raw
    address = email.from_address

    if not raw_from.strip():
        return make_evidence(
            "header_auth",
            "缺少 From 头",
            "邮件没有可解析的 From 头，无法确认发件人身份。",
            0.70,
            confidence=0.95,
            source=SOURCE,
            tags=["missing_from"],
            raw={"from_raw": raw_from},
        )

    malformed = (
        not address
        or address.count("@") != 1
        or not email.from_domain
        or bool(_MALFORMED_ADDRESS_RE.search(address))
    )
    if malformed:
        return make_evidence(
            "header_auth",
            "From 头格式异常",
            f"From 原始值“{raw_from}”无法解析为有效的邮箱地址。",
            0.55,
            confidence=0.90,
            source=SOURCE,
            tags=["malformed_from"],
            raw={"from_raw": raw_from, "parsed_address": address},
        )

    if "." not in email.from_domain and email.from_domain not in {"localhost"}:
        return make_evidence(
            "header_auth",
            "发件域缺少有效顶级域",
            f"From 域“{email.from_domain}”不具备常规的顶级域结构。",
            0.35,
            confidence=0.75,
            source=SOURCE,
            tags=["malformed_from"],
            raw={"from_raw": raw_from, "from_domain": email.from_domain},
        )
    return None


def _mitigating_evidence(
    details: dict[str, dict[str, str]], email: EmailMessage
) -> Evidence | None:
    """Reward genuinely authenticated mail with one bounded mitigation item."""
    spf = details["spf"]["value"]
    dkim = details["dkim"]["value"]
    dmarc = details["dmarc"]["value"]
    if spf != "pass" or dkim != "pass" or dmarc in {"fail", "permerror"}:
        return None
    tags = ["auth_pass"]
    # A pass for the organization's own domain is stronger than a pass for an
    # arbitrary attacker-owned domain: it lets policy distinguish an internal
    # security-awareness bulletin from an external injection attempt.
    from ..config import internal_domains

    if email.from_domain in internal_domains():
        tags.append("trusted_internal")
    return make_evidence(
        "header_auth",
        "发件域认证通过",
        f"SPF 与 DKIM 均通过（DMARC={dmarc}），发件身份具备可验证的认证链。",
        0.40,
        confidence=0.90,
        source=SOURCE,
        tags=tags,
        raw={
            "spf": spf,
            "dkim": dkim,
            "dmarc": dmarc,
            "spf_origin": details["spf"]["origin"],
            "dkim_origin": details["dkim"]["origin"],
            "dmarc_origin": details["dmarc"]["origin"],
            "internal_domain": "trusted_internal" in tags,
        },
        polarity="mitigating",
    )


def analyze_headers(email: EmailMessage) -> list[Evidence]:
    """Return deterministic header/authentication evidence for ``email``."""
    details = _result_details(email)
    evidence: list[Evidence] = []

    auth_item = _auth_evidence(details)
    if auth_item is not None:
        # Keep the sender domain in the raw record so the report is auditable.
        auth_item.raw["from_domain"] = email.from_domain
        evidence.append(auth_item)

    for builder in (
        _reply_to_evidence,
        _return_path_evidence,
        _display_mismatch_evidence,
        _malformed_from_evidence,
    ):
        item = builder(email)
        if item is not None:
            evidence.append(item)

    mitigation = _mitigating_evidence(details, email)
    if mitigation is not None:
        evidence.append(mitigation)
    return evidence
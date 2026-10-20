"""Content-level social-engineering analysis.

The detector aggregates individual keywords into at most five human-readable
findings (urgency, credential request, authority/CEO, payment change, and
secrecy/reward/generic greeting).  Each finding reports the exact phrases that
matched so an analyst can audit the conclusion; no keyword is ever turned into
evidence without a literal match in the subject or body.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

from ..models import EmailMessage, Evidence, make_evidence

SOURCE = "text_analysis"
MAX_EVIDENCE = 5


@dataclass(frozen=True)
class _PhraseGroup:
    key: str
    title: str
    tag: str
    strong: tuple[str, ...]
    weak: tuple[str, ...]
    base_severity: float
    max_severity: float = 0.68
    min_matches: int = 1
    require_strong: bool = False
    confidence: float = 0.82


_GROUPS: tuple[_PhraseGroup, ...] = (
    _PhraseGroup(
        key="urgency",
        title="紧迫感与威胁性话术",
        tag="urgency",
        strong=(
            "account will be locked",
            "account will be suspended",
            "account will be closed",
            "final warning",
            "last warning",
            "immediate action required",
            "within 2 hours",
            "within 24 hours",
            "within 48 hours",
            "expires today",
            "will expire",
            "act now",
            "account closure",
            "立即处理",
            "立即验证",
            "账户将被锁定",
            "账户将被冻结",
            "即将冻结",
            "即将停用",
            "最后警告",
            "最后通知",
            "限时",
            "24小时内",
            "2小时内",
            "48小时内",
        ),
        weak=(
            "urgent",
            "immediately",
            "as soon as possible",
            "right away",
            "do not delay",
            "time-sensitive",
            "important notice",
            "紧急",
            "立即",
            "马上",
            "尽快",
            "紧急通知",
        ),
        base_severity=0.20,
    ),
    _PhraseGroup(
        key="credential",
        title="索取凭据/诱导登录",
        tag="credential_language",
        strong=(
            "click here to verify",
            "click the link to verify",
            "enter your password",
            "confirm your password",
            "verify your account",
            "verify your identity",
            "login to your account",
            "sign in to your account",
            "update your password",
            "reset your password",
            "one-time password",
            "verification code",
            "account verification",
            "输入密码",
            "验证码",
            "动态码",
            "点击链接验证",
            "点击此处验证",
            "账户验证",
            "身份验证",
            "重置密码",
            "登录密码",
        ),
        weak=(
            "password",
            "login",
            "log in",
            "sign in",
            "credentials",
            "otp",
            "unlock your account",
            "密码",
            "登录",
            "登陆",
            "账号",
            "账户",
            "凭证",
            "验证",
            "点击此处",
        ),
        base_severity=0.20,
        confidence=0.84,
    ),
    _PhraseGroup(
        key="authority",
        title="冒充权威或高管",
        tag="ceo_fraud",
        strong=(
            "chief executive officer",
            "chief financial officer",
            "ceo",
            "cfo",
            "coo",
            "cto",
            "president",
            "chairman of the board",
            "board of directors",
            "executive team",
            "董事长",
            "总裁",
            "首席执行官",
            "首席财务官",
            "总经理",
            "高管",
        ),
        weak=(
            "executive",
            "director",
            "finance department",
            "accounting department",
            "human resources",
            "hr department",
            "legal department",
            "payroll department",
            "财务部",
            "人事部",
            "法务部",
            "领导",
            "老板",
            "公司高层",
        ),
        base_severity=0.20,
        confidence=0.78,
        # Generic department names ("finance department", "HR") are far too
        # common in legitimate mail to be floor-eligible on their own.
        require_strong=True,
    ),
    _PhraseGroup(
        key="payment",
        title="付款/账户变更指令",
        tag="payment_change",
        strong=(
            "wire transfer",
            "wire the funds",
            "transfer the funds",
            "bank account changed",
            "bank account has changed",
            "new bank account",
            "change of bank details",
            "update bank details",
            "update payment details",
            "purchase gift cards",
            "gift card",
            "gift cards",
            "routing number",
            "swift code",
            "iban",
            "remittance",
            "更改收款账户",
            "银行账户变更",
            "账户变更",
            "收款账号变更",
            "购买礼品卡",
            "礼品卡",
            "转账",
            "汇款",
            "电汇",
            "收款账户",
        ),
        weak=(
            "bank details",
            "bank account",
            "payment details",
            "invoice",
            "payment",
            "wire",
            "发票",
            "付款",
            "货款",
            "银行账号",
            "收款账号",
            "充值卡",
        ),
        base_severity=0.20,
        confidence=0.82,
        # "invoice"/"payment" alone is normal accounts-payable language; the
        # BEC floor requires an explicit bank-account/wire/gift-card change.
        require_strong=True,
    ),
    _PhraseGroup(
        key="social",
        title="保密、利益诱导或泛化称呼",
        tag="social_engineering",
        strong=(
            "do not tell anyone",
            "keep this confidential",
            "keep this secret",
            "between you and me",
            "you have won",
            "you are a winner",
            "claim your prize",
            "claim your reward",
            "恭喜中奖",
            "恭喜您中奖",
            "领取奖品",
            "领取奖励",
            "不要告诉任何人",
            "严格保密",
        ),
        weak=(
            "confidential",
            "prize",
            "reward",
            "bonus",
            "gift",
            "dear user",
            "dear customer",
            "dear valued customer",
            "dear sir",
            "dear madam",
            "valued customer",
            "尊敬的用户",
            "亲爱的用户",
            "您好",
        ),
        base_severity=0.15,
        max_severity=0.50,
        min_matches=2,
        confidence=0.72,
    ),
)


def _analysis_text(email: EmailMessage) -> str:
    """Subject + plain body, with an HTML-stripped fallback."""
    parts = [email.subject, email.body_text]
    if not email.body_text and email.body_html:
        parts.append(re.sub(r"<[^>]+>", " ", email.body_html))
    return html.unescape("\n".join(part for part in parts if part))


def _phrase_present(text: str, phrase: str) -> bool:
    """Case-insensitive match with ASCII word boundaries where possible."""
    phrase = phrase.lower()
    if phrase.isascii():
        words = [re.escape(word) for word in phrase.split()]
        pattern = r"(?<![a-z0-9])" + r"\s+".join(words) + r"(?![a-z0-9])"
        return re.search(pattern, text) is not None
    return phrase in text


def _matched_phrases(text: str, group: _PhraseGroup) -> tuple[list[str], int]:
    """Return distinct matched phrases (longest first) and strong-match count."""
    ordered = sorted(
        dict.fromkeys([*group.strong, *group.weak]),
        key=len,
        reverse=True,
    )
    matched: list[str] = []
    for phrase in ordered:
        if not _phrase_present(text, phrase):
            continue
        # Drop a weaker phrase that is already covered by a longer match, so
        # "password" does not inflate a "enter your password" hit.
        lowered = phrase.lower()
        if any(lowered in existing.lower() for existing in matched):
            continue
        matched.append(phrase)
    strong_set = {phrase.lower() for phrase in group.strong}
    strong_count = sum(1 for phrase in matched if phrase.lower() in strong_set)
    return matched, strong_count


def _severity(group: _PhraseGroup, count: int, strong_count: int) -> float:
    """Scale with the number and strength of distinct phrase hits."""
    value = group.base_severity
    value += 0.16 * max(0, count - 1)
    value += 0.10 * min(strong_count, 2)
    return round(min(group.max_severity, value), 2)


def _group_evidence(
    group: _PhraseGroup, matched: list[str], strong_count: int
) -> Evidence:
    shown = "、".join(f"“{phrase}”" for phrase in matched[:8])
    more = "" if len(matched) <= 8 else f" 等 {len(matched)} 处"
    detail = (
        f"命中 {len(matched)} 个特征短语（强特征 {strong_count} 个）："
        f"{shown}{more}。"
    )
    return make_evidence(
        "content",
        group.title,
        detail,
        _severity(group, len(matched), strong_count),
        confidence=min(0.92, group.confidence + 0.02 * len(matched)),
        source=SOURCE,
        tags=[group.tag],
        raw={
            "group": group.key,
            "matched_phrases": matched,
            "match_count": len(matched),
            "strong_count": strong_count,
        },
    )


def analyze_text(email: EmailMessage) -> list[Evidence]:
    """Return at most five aggregated social-engineering evidence items."""
    text = _analysis_text(email).lower()
    if not text.strip():
        return []

    evidence: list[Evidence] = []
    for group in _GROUPS:
        matched, strong_count = _matched_phrases(text, group)
        if not matched:
            continue
        if len(matched) < group.min_matches:
            continue
        if group.require_strong and strong_count == 0:
            continue
        evidence.append(_group_evidence(group, matched, strong_count))
        if len(evidence) >= MAX_EVIDENCE:
            break
    return evidence
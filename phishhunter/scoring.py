"""Deterministic evidence fusion and policy enforcement.

Design rule: **evidence beats opinion**.  The deterministic scorer owns the
score; an LLM may only nudge it by a bounded amount and can never push a
critical finding below its floor.  This is what makes the agent robust to
hallucination and prompt injection.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable

from .models import (
    POLARITY_MITIGATING,
    POLARITY_RISK,
    Evidence,
    ScoreBreakdown,
    clamp,
)

# Category weights sum to 1.0.  No single category can dominate the score;
# cross-category corroboration is required to reach the top bands.
CATEGORY_WEIGHTS: dict[str, float] = {
    "header_auth": 0.14,
    "sender_identity": 0.18,
    "url": 0.22,
    "attachment": 0.12,
    "content": 0.12,
    "image": 0.06,
    "prompt_injection": 0.08,
    "threat_intel": 0.08,
}

CATEGORY_LABELS: dict[str, str] = {
    "header_auth": "邮件认证",
    "sender_identity": "发件人身份",
    "url": "链接",
    "attachment": "附件",
    "content": "正文语义",
    "image": "图片/二维码",
    "prompt_injection": "提示注入",
    "threat_intel": "威胁情报",
}


@dataclass(frozen=True)
class FloorRule:
    """A policy floor triggered by tags on deterministic evidence."""

    floor: float
    reason: str
    required: frozenset[str] = frozenset()
    any_of: frozenset[str] = frozenset()
    unless_mitigating: frozenset[str] = frozenset()

    def matches(self, tags: set[str], mitigating_tags: set[str] | None = None) -> bool:
        if self.unless_mitigating & (mitigating_tags or set()):
            return False
        if not self.required.issubset(tags):
            return False
        if self.any_of and not (self.any_of & tags):
            return False
        return True


# Tags are emitted by detectors/tools.  Keep the vocabulary small and stable.
FLOOR_RULES: tuple[FloorRule, ...] = (
    FloorRule(95, "威胁情报确认该 URL 为恶意", frozenset({"known_malicious_url"})),
    FloorRule(95, "威胁情报确认该附件哈希为恶意", frozenset({"known_malicious_file"})),
    FloorRule(88, "沙箱发现凭据窃取页面", frozenset({"credential_harvest"})),
    FloorRule(
        85,
        "二维码载荷指向高风险页面",
        frozenset({"qr_payload"}),
        frozenset({"brand_spoof", "domain_new", "credential_harvest"}),
    ),
    FloorRule(
        75,
        "二维码载荷指向 IP/短链/凭据页面",
        frozenset({"qr_payload"}),
        frozenset(
            {
                "ip",
                "ip_literal",
                "shortener",
                "punycode",
                "credential_path",
                "credential_language",
                "domain_new",
                "brand_spoof",
                "credential_harvest",
            }
        ),
    ),
    FloorRule(85, "附件使用危险的双扩展名", frozenset({"double_extension"})),
    FloorRule(
        82,
        "新注册域名叠加身份或认证异常",
        frozenset({"domain_new"}),
        frozenset({"brand_spoof", "auth_fail", "credential_language"}),
    ),
    FloorRule(
        78,
        "品牌仿冒叠加邮件认证失败",
        frozenset({"brand_spoof"}),
        frozenset({"auth_fail", "domain_new"}),
    ),
    FloorRule(78, "短链接跳转到 IP 地址或凭据页", frozenset({"redirect_ip"})),
    FloorRule(
        78,
        "短链接跳转到凭据页面",
        frozenset({"shortener"}),
        frozenset({"credential_path", "credential_harvest", "credential_language"}),
    ),
    FloorRule(
        75,
        "跳转链接指向凭据页面",
        frozenset({"redirect"}),
        frozenset({"credential_path", "credential_harvest"}),
    ),
    FloorRule(
        82,
        "CEO 欺诈叠加付款变更且来自免费邮箱",
        frozenset({"ceo_fraud", "payment_change", "free_mail"}),
    ),
    FloorRule(
        76,
        "CEO 欺诈叠加付款变更指令",
        frozenset({"ceo_fraud", "payment_change"}),
    ),
    FloorRule(75, "邮件包含可执行附件", frozenset({"executable_attachment"})),
    FloorRule(
        72,
        "外部来源的提示注入叠加认证/域名异常",
        frozenset({"instruction_override"}),
        frozenset({"auth_fail", "domain_new", "hidden_content"}),
    ),
    FloorRule(
        72,
        "认证失败叠加凭据窃取话术",
        frozenset({"auth_fail", "credential_language"}),
    ),
    FloorRule(
        68,
        "隐藏文本内容叠加邮件认证异常",
        frozenset({"hidden_content"}),
        frozenset({"auth_fail", "domain_new", "instruction_override"}),
    ),
    FloorRule(65, "发件域疑似品牌仿冒", frozenset({"brand_spoof"})),
    FloorRule(65, "发件域使用 Punycode 混淆", frozenset({"punycode"})),
    FloorRule(
        45,
        "缺少或无法解析 From 头",
        any_of=frozenset({"missing_from", "malformed_from"}),
    ),
    # Credential language turns an identity/obfuscation signal into a clear
    # account-takeover attempt (brand impersonation is never needed for a
    # legitimate password page on the brand's own domain).
    FloorRule(
        78,
        "品牌仿冒叠加凭据索取话术",
        frozenset({"brand_spoof", "credential_language"}),
    ),
    FloorRule(
        78,
        "Punycode 混淆叠加凭据索取话术",
        frozenset({"punycode", "credential_language"}),
    ),
    # A hidden/encoded instruction becomes actionable when it is paired with a
    # credential request.  Injection alone stays advisory so an internal
    # security-awareness email that quotes an attack is not auto-blocked.
    FloorRule(
        72,
        "提示注入叠加凭据索取话术",
        frozenset({"credential_language"}),
        frozenset(
            {"instruction_override", "verdict_steering", "fake_tool_result", "role_manipulation"}
        ),
        # An authenticated internal awareness email may legitimately quote an
        # attack phrase while discussing password hygiene.
        frozenset({"trusted_internal"}),
    ),
    FloorRule(70, "链接使用脚本或数据 URI", frozenset({"script_uri"})),
    FloorRule(
        72,
        "@ 混淆链接叠加凭据话术",
        frozenset({"authority_at", "credential_language"}),
    ),
)


MITIGATION_PER_WEIGHT = 10.0
MAX_MITIGATION = 15.0


def _noisy_or(weights: Iterable[float]) -> float:
    """Combine independent risk signals without letting them exceed 1.0."""
    product = 1.0
    for weight in weights:
        product *= 1.0 - clamp(weight)
    return 1.0 - product


def matching_floors(evidence: Iterable[Evidence]) -> tuple[float | None, list[str]]:
    tags: set[str] = set()
    mitigating_tags: set[str] = set()
    for item in evidence:
        if item.polarity == POLARITY_RISK:
            tags.update(item.tags)
        else:
            mitigating_tags.update(item.tags)
    matched = [
        rule for rule in FLOOR_RULES if rule.matches(tags, mitigating_tags)
    ]
    if not matched:
        return None, []
    floor = max(rule.floor for rule in matched)
    reasons: list[str] = []
    for rule in sorted(matched, key=lambda r: r.floor, reverse=True):
        if rule.reason not in reasons:
            reasons.append(rule.reason)
    return float(floor), reasons


def score_evidence(
    evidence: Iterable[Evidence],
    *,
    block_threshold: int = 70,
    quarantine_threshold: int = 40,
) -> ScoreBreakdown:
    evidence = list(evidence)
    risk_by_category: dict[str, list[float]] = defaultdict(list)
    mitigation_total = 0.0

    for item in evidence:
        weight = item.weight()
        if item.polarity == POLARITY_MITIGATING:
            mitigation_total += weight * MITIGATION_PER_WEIGHT
            continue
        risk_by_category[item.category].append(weight)

    category_scores: dict[str, float] = {}
    contributions: dict[str, float] = {}
    raw = 0.0
    for category, weight in CATEGORY_WEIGHTS.items():
        cat_risk = _noisy_or(risk_by_category.get(category, []))
        category_scores[category] = round(cat_risk, 4)
        contribution = cat_risk * weight * 100.0
        contributions[category] = round(contribution, 2)
        raw += contribution

    mitigation = min(MAX_MITIGATION, mitigation_total)
    raw = clamp(raw - mitigation, 0.0, 100.0)
    floor, floor_reasons = matching_floors(evidence)
    pre_llm = max(raw, floor or 0.0)
    pre_llm = clamp(pre_llm, 0.0, 100.0)

    confidence = estimate_confidence(evidence, floor)

    return ScoreBreakdown(
        raw_score=round(raw, 1),
        pre_llm_score=round(pre_llm, 1),
        final_score=round(pre_llm, 1),
        category_scores=category_scores,
        category_contributions=contributions,
        mitigation_points=round(mitigation, 1),
        floor=floor,
        floor_reasons=floor_reasons,
        llm_adjustment=0.0,
        confidence=confidence,
        risk_level=risk_level_for(pre_llm, block_threshold, quarantine_threshold),
    )


def estimate_confidence(
    evidence: Iterable[Evidence], floor: float | None = None
) -> float:
    evidence = list(evidence)
    risk = [e for e in evidence if e.polarity == POLARITY_RISK]
    verified = [e for e in risk if e.verifiable and e.confidence >= 0.7]
    sources = {e.source for e in evidence if e.source}
    confidence = 0.52 + min(0.28, 0.045 * len(verified)) + min(0.10, 0.02 * len(sources))
    if floor:
        confidence += 0.08
    if not risk:
        confidence = max(confidence, 0.55)
    return round(clamp(confidence, 0.30, 0.97), 2)


def apply_llm_adjustment(
    breakdown: ScoreBreakdown,
    suggested_score: float | None,
    *,
    cited_ids: list[str],
    valid_ids: set[str],
    llm_confidence: float,
    max_delta: float = 8.0,
) -> float:
    """Apply a small, citation-gated adjustment; never weaken a hard floor."""
    valid_citations = [cid for cid in cited_ids if cid in valid_ids]
    if suggested_score is None or len(valid_citations) < 2 or llm_confidence < 0.4:
        breakdown.llm_adjustment = 0.0
        breakdown.final_score = breakdown.pre_llm_score
        breakdown.risk_level = classify_score(breakdown.final_score)
        return 0.0

    # The model was shown ``pre_llm_score`` as the deterministic baseline.
    # Adjusting from the raw pre-floor score would double-count the floor
    # (e.g. raw 87 -> floor 95 -> model agrees -> +8 -> 100).  Anchor the
    # delta at the score the model actually saw.
    delta = clamp(suggested_score - breakdown.pre_llm_score, -max_delta, max_delta)
    if breakdown.floor is not None and delta < 0:
        # The model wants to lower a score justified by critical evidence.
        delta = 0.0
    final = clamp(breakdown.pre_llm_score + delta, breakdown.floor or 0.0, 100.0)
    breakdown.llm_adjustment = round(delta, 1)
    breakdown.final_score = round(final, 1)
    breakdown.risk_level = classify_score(final)
    return round(delta, 1)


def classify_score(score: float) -> str:
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def risk_level_for(
    score: float, block_threshold: int = 70, quarantine_threshold: int = 40
) -> str:
    # Keep the human-facing band aligned with the action thresholds.
    if score >= max(85, block_threshold):
        return "Critical" if score >= 85 else "High"
    if score >= block_threshold:
        return "High"
    if score >= quarantine_threshold:
        return "Medium"
    return "Low"


def recommend_action(
    score: float, block_threshold: int = 70, quarantine_threshold: int = 40
) -> str:
    if score >= block_threshold:
        return "Block"
    if score >= quarantine_threshold:
        return "Quarantine"
    return "Allow"
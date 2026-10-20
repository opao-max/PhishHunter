"""Sender identity and brand-impersonation analysis.

The detector never calls WHOIS/DNS: it only reasons over the header strings.
That keeps it deterministic, offline and cheap while still catching the most
common lookalike-domain tricks:

* homoglyph domains (``micr0soft-security.com``)
* punycode-encoded internationalised domains (``xn--...``)
* a brand shown in the display name that does not own the sender domain
* free mailbox providers used to impersonate an executive or company role

False positives matter here: ``company.com``, ``github.com`` and ordinary
vendor domains must pass silently.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Iterable

from ..models import EmailMessage, Evidence, make_evidence

SOURCE = "sender_identity"

BRANDS: tuple[str, ...] = (
    "microsoft",
    "outlook",
    "office365",
    "paypal",
    "apple",
    "icloud",
    "google",
    "gmail",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
    "bank",
    "chase",
    "wellsfargo",
    "dhl",
    "fedex",
    "ups",
    "alipay",
    "wechat",
    "tencent",
    "taobao",
    "jd",
    "unionpay",
)

# Short/generic brand words are only suspicious when paired with a lure word.
_GENERIC_BRANDS = {"bank", "ups", "jd", "dhl", "fed"}

# Tokens that turn a brand-looking domain into a credential lure.
_SUFFIX_TOKENS = {
    "security",
    "secure",
    "login",
    "signin",
    "verify",
    "verification",
    "support",
    "account",
    "update",
    "service",
    "auth",
    "billing",
    "payment",
    "invoice",
    "wallet",
    "help",
    "alert",
    "notice",
    "team",
    "mail",
    "email",
    "delivery",
    "express",
    "shipping",
    "tracking",
    "parcel",
    "recovery",
    "unlock",
    "confirm",
    "customer",
    "center",
    "online",
    "official",
    "server",
    "web",
    "portal",
    "sso",
    "cloud",
    "docs",
    "drive",
    "share",
    "file",
    "payroll",
    "id",
    "my",
}

# Official registrable domains per brand.  A domain matches when it equals one
# of these or is a subdomain of one.
OFFICIAL_DOMAINS: dict[str, set[str]] = {
    "microsoft": {
        "microsoft.com",
        "microsoftonline.com",
        "microsoftstore.com",
        "microsoft365.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "xbox.com",
    },
    "outlook": {"outlook.com", "hotmail.com", "live.com", "office.com", "microsoft.com"},
    "office365": {"office365.com", "office.com", "microsoft.com", "microsoftonline.com"},
    "paypal": {"paypal.com", "paypal.me"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "icloud": {"icloud.com", "me.com", "apple.com"},
    "google": {"google.com", "googlemail.com", "gmail.com", "youtube.com", "google.cn"},
    "gmail": {"gmail.com", "googlemail.com", "google.com"},
    "amazon": {"amazon.com", "amazon.cn", "amazon.co.uk", "amazon.de", "amazonaws.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "bank": {
        "bankofamerica.com",
        "citibank.com",
        "chase.com",
        "wellsfargo.com",
        "icbc.com.cn",
        "ccb.com",
        "boc.cn",
        "cmbchina.com",
        "abchina.com",
    },
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "alipay": {"alipay.com", "alipay.cn"},
    "wechat": {"wechat.com", "weixin.qq.com", "qq.com"},
    "tencent": {"tencent.com", "qq.com", "weixin.qq.com"},
    "taobao": {"taobao.com", "tmall.com"},
    "jd": {"jd.com", "jd.hk"},
    "unionpay": {"unionpay.com", "unionpay.cn", "95516.com"},
}

# Chinese / localised brand names commonly used in display names.
BRAND_ALIASES: dict[str, str] = {
    "微软": "microsoft",
    "苹果": "apple",
    "亚马逊": "amazon",
    "谷歌": "google",
    "脸书": "facebook",
    "网飞": "netflix",
    "贝宝": "paypal",
    "支付宝": "alipay",
    "微信": "wechat",
    "腾讯": "tencent",
    "淘宝": "taobao",
    "京东": "jd",
    "银联": "unionpay",
    "联邦快递": "fedex",
    "敦豪": "dhl",
    "office 365": "office365",
}

FREE_MAIL_DOMAINS: set[str] = {
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

# Role / authority terms that make a free mailbox suspicious.
_AUTHORITY_TERMS: tuple[str, ...] = (
    "ceo",
    "cfo",
    "coo",
    "cto",
    "chief executive",
    "chief financial",
    "president",
    "chairman",
    "director",
    "executive",
    "board",
    "finance",
    "financial",
    "accounting",
    "payroll",
    "human resources",
    "hr department",
    "legal department",
    "payments team",
    "accounts payable",
    "accounts department",
    "billing department",
    "it support",
    "support team",
    "help desk",
    "董事长",
    "总裁",
    "总经理",
    "首席执行官",
    "首席财务官",
    "财务",
    "财务部",
    "人事",
    "人事部",
    "法务",
    "法务部",
    "客服",
    "技术支持",
    "高管",
    "领导",
    "老板",
)

# Money-movement terms.  A single generic hit (e.g. a freelancer's invoice) is
# not enough on its own; two distinct hits corroborate a payment-fraud lure.
_PAYMENT_TERMS: tuple[str, ...] = (
    "wire transfer",
    "bank account",
    "payment",
    "remittance",
    "invoice",
    "gift card",
    "gift cards",
    "转账",
    "汇款",
    "付款",
    "工资",
    "发薪",
)

_MULTI_REPLACEMENTS: tuple[tuple[str, str], ...] = (
    ("rn", "m"),
    ("vv", "w"),
    ("cl", "d"),
)

# ``1`` is ambiguous between ``l`` and ``i``; both readings are generated.
_CHAR_MAP_L = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a"})
_CHAR_MAP_I = str.maketrans({"0": "o", "1": "i", "3": "e", "5": "s", "@": "a"})

# Non-ASCII characters that are visually identical (or near-identical) to
# Latin letters.  Attackers use Cyrillic/Greek lookalikes to build domains such
# as ``mіcrоsoft.example`` that no ASCII-only homoglyph map can catch.
_CONFUSABLE_CHARS: dict[str, str] = {
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s",
    "і": "i", "ї": "i", "ј": "j", "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h",
    "ӏ": "l", "ɡ": "g", "ѵ": "v", "ѡ": "w", "ү": "y",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o",
    "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "γ": "y",
}
_CONFUSABLE_MAP = str.maketrans(_CONFUSABLE_CHARS)


def fold_confusables(value: str) -> str:
    """NFKC-normalise text and fold common Cyrillic/Greek visual lookalikes."""
    normalized = unicodedata.normalize("NFKC", str(value or "")).lower()
    return normalized.translate(_CONFUSABLE_MAP)

_KIND_SEVERITY: dict[str, float] = {
    "exact": 0.72,
    "fuzzy": 0.80,
    "brand_suffix": 0.72,
    "suffix_brand": 0.72,
    "embedded_official": 0.85,
}

_KIND_LABEL: dict[str, str] = {
    "exact": "品牌名同形",
    "fuzzy": "品牌名近似（编辑距离≤1）",
    "brand_suffix": "品牌名+诱导后缀",
    "suffix_brand": "诱导前缀+品牌名",
    "embedded_official": "官方域名嵌入伪域名",
}


# --------------------------------------------------------------------------- #
# text helpers
# --------------------------------------------------------------------------- #


def _tokenize(domain: str) -> list[str]:
    """Split a domain into comparable tokens (``a-b.c`` -> a, b, c)."""
    return [token for token in re.split(r"[-_.]+", (domain or "").lower()) if token]


def _normalize_variants(token: str) -> list[str]:
    """Apply Unicode/ASCII homoglyph normalization, returning both readings."""
    token = fold_confusables(token)

    def apply(mapping: dict[int, str]) -> str:
        value = token
        for source, target in _MULTI_REPLACEMENTS:
            value = value.replace(source, target)
        return value.translate(mapping)

    with_l = apply(_CHAR_MAP_L)
    with_i = apply(_CHAR_MAP_I)
    return [with_l] if with_l == with_i else [with_l, with_i]


def _levenshtein(left: str, right: str) -> int:
    """Small standard-library Levenshtein distance."""
    if left == right:
        return 0
    if abs(len(left) - len(right)) > 2:
        return 3
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, start=1):
        current = [i]
        for j, char_right in enumerate(right, start=1):
            insertion = current[j - 1] + 1
            deletion = previous[j] + 1
            substitution = previous[j - 1] + (char_left != char_right)
            current.append(min(insertion, deletion, substitution))
        previous = current
    return previous[-1]


def _is_official(domain: str, brand: str) -> bool:
    """True when ``domain`` is, or is a subdomain of, the brand's real domain."""
    for official in OFFICIAL_DOMAINS.get(brand, ()):
        if domain == official or domain.endswith("." + official):
            return True
    return False


def _embedded_official(domain: str, brand: str) -> str:
    """Return an official domain embedded mid-string, e.g. ``ups.com.evil``."""
    padded = "." + domain.strip(".") + "."
    for official in OFFICIAL_DOMAINS.get(brand, ()):
        if "." + official + "." in padded and not padded.endswith("." + official + "."):
            return official
    return ""


def _has_lure_suffix(tokens: Iterable[str], brand: str) -> bool:
    for token in tokens:
        for normalized in _normalize_variants(token):
            if normalized in _SUFFIX_TOKENS and normalized != brand:
                return True
    return False


def _contains_term(text: str, term: str) -> bool:
    text = (text or "").lower()
    term = term.lower()
    if term.isascii():
        pattern = r"(?<![a-z0-9])" + re.escape(term) + r"(?![a-z0-9])"
        return re.search(pattern, text) is not None
    return term in text


# --------------------------------------------------------------------------- #
# brand analysis
# --------------------------------------------------------------------------- #


def _domain_brand_signals(domain: str) -> list[dict[str, str]]:
    """Return de-duplicated brand-impersonation signals for a sender domain."""
    domain = (domain or "").strip().lower().rstrip(".")
    tokens = _tokenize(domain)
    signals: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(brand: str, kind: str, token: str, normalized: str) -> None:
        key = (brand, kind)
        if key in seen:
            return
        seen.add(key)
        signals.append(
            {
                "brand": brand,
                "kind": kind,
                "token": token,
                "normalized": normalized,
            }
        )

    for brand in BRANDS:
        embedded = _embedded_official(domain, brand)
        if embedded:
            add(brand, "embedded_official", embedded, domain)

    for token in tokens:
        variants = _normalize_variants(token)
        for brand in BRANDS:
            if _is_official(domain, brand):
                continue
            for normalized in variants:
                if normalized == brand:
                    if brand in _GENERIC_BRANDS and not _has_lure_suffix(tokens, brand):
                        continue
                    add(brand, "exact", token, normalized)
                elif (
                    len(normalized) >= 5
                    and len(brand) >= 5
                    and _levenshtein(normalized, brand) <= 1
                ):
                    add(brand, "fuzzy", token, normalized)
                elif normalized.startswith(brand):
                    remainder = normalized[len(brand) :]
                    if remainder in _SUFFIX_TOKENS:
                        add(brand, "brand_suffix", token, normalized)
                elif normalized.endswith(brand):
                    prefix = normalized[: -len(brand)]
                    if prefix in _SUFFIX_TOKENS:
                        add(brand, "suffix_brand", token, normalized)
    return signals


def _display_brands(display: str) -> list[str]:
    """Brands explicitly named in the display name (English or Chinese)."""
    text = (display or "").lower()
    found: list[str] = []
    for brand in BRANDS:
        if brand in _GENERIC_BRANDS:
            continue
        if re.search(
            r"(?<![a-z0-9])" + re.escape(brand) + r"(?![a-z0-9])", text
        ):
            found.append(brand)
    for alias, brand in BRAND_ALIASES.items():
        if alias in text:
            found.append(brand)
    # Preserve order, drop duplicates.
    return list(dict.fromkeys(found))


def _decode_punycode(domain: str) -> str:
    """Best-effort decoding of ``xn--`` labels; empty string when invalid."""
    labels: list[str] = []
    try:
        for label in (domain or "").split("."):
            if label.startswith("xn--"):
                labels.append(label.encode("ascii").decode("idna"))
            else:
                labels.append(label)
    except (UnicodeError, ValueError):
        return ""
    return ".".join(labels)


# --------------------------------------------------------------------------- #
# evidence builders
# --------------------------------------------------------------------------- #


def _brand_evidence(
    email: EmailMessage,
    signals: list[dict[str, str]],
    display_brands: list[str],
    display_mismatch: list[str],
    decoded_domain: str,
) -> Evidence | None:
    if not signals and not display_mismatch:
        return None

    severity = 0.0
    for signal in signals:
        severity = max(severity, _KIND_SEVERITY.get(signal["kind"], 0.65))
    if display_mismatch:
        severity = max(severity, 0.70)
    if signals and display_mismatch:
        severity = min(0.88, severity + 0.03)

    parts: list[str] = []
    if signals:
        rendered = "、".join(
            f"{item['brand']}（{_KIND_LABEL.get(item['kind'], item['kind'])}，"
            f"令牌“{item['token']}”→“{item['normalized']}”）"
            for item in signals[:4]
        )
        parts.append(f"发件域 {email.from_domain} 疑似仿冒品牌：{rendered}。")
    if display_mismatch:
        parts.append(
            f"显示名声称属于品牌 {', '.join(display_mismatch)}，"
            f"但发件域 {email.from_domain} 并非其官方域名。"
        )
    if decoded_domain and decoded_domain != email.from_domain:
        parts.append(f"Punycode 解码结果为 {decoded_domain}。")

    return make_evidence(
        "sender_identity",
        "发件人身份疑似品牌仿冒",
        "".join(parts),
        severity,
        confidence=0.86 if signals else 0.80,
        source=SOURCE,
        tags=["brand_spoof"],
        raw={
            "from_domain": email.from_domain,
            "from_display": email.from_display,
            "tokens": _tokenize(email.from_domain),
            "signals": signals,
            "display_brands": display_brands,
            "display_mismatch": display_mismatch,
            "decoded_domain": decoded_domain,
        },
    )


def _punycode_evidence(email: EmailMessage, decoded: str) -> Evidence | None:
    labels = [label for label in email.from_domain.split(".") if label.startswith("xn--")]
    if not labels:
        return None
    detail = f"发件域 {email.from_domain} 含 Punycode 标签：{', '.join(labels)}。"
    if decoded and decoded != email.from_domain:
        detail += f"解码后为 {decoded}，常用于伪装成视觉相似的国际域名。"
    return make_evidence(
        "sender_identity",
        "发件域使用 Punycode 混淆",
        detail,
        0.80,
        confidence=0.90,
        source=SOURCE,
        tags=["punycode"],
        raw={
            "from_domain": email.from_domain,
            "labels": labels,
            "decoded": decoded,
        },
    )


def _free_mail_evidence(
    email: EmailMessage, display_brands: list[str]
) -> Evidence | None:
    domain = email.from_domain
    if domain not in FREE_MAIL_DOMAINS:
        return None

    haystacks = (email.from_display, email.subject)
    authority_matched = [
        term
        for term in _AUTHORITY_TERMS
        if any(_contains_term(text, term) for text in haystacks)
    ]
    payment_matched = [
        term
        for term in _PAYMENT_TERMS
        if any(_contains_term(text, term) for text in haystacks)
    ]
    matched = authority_matched + payment_matched
    has_role_context = (
        bool(authority_matched) or bool(display_brands) or len(payment_matched) >= 2
    )
    if not has_role_context:
        return None

    severity = 0.62 if display_brands else 0.60
    detail = (
        f"发件人使用免费邮箱 {domain}，但显示名/主题带有企业或权威语境"
        f"（显示名“{email.from_display or '空'}”，命中："
        f"{'、'.join(matched[:6]) or '品牌名'}）。"
        "免费邮箱无法代表企业官方身份，符合高管冒充类社会工程特征。"
    )
    return make_evidence(
        "sender_identity",
        "免费邮箱冒充企业/权威身份",
        detail,
        severity,
        confidence=0.82,
        source=SOURCE,
        tags=["free_mail"],
        raw={
            "from_domain": domain,
            "from_display": email.from_display,
            "subject": email.subject,
            "matched_terms": matched,
            "authority_terms": authority_matched,
            "payment_terms": payment_matched,
            "display_brands": display_brands,
        },
    )


def analyze_sender(email: EmailMessage) -> list[Evidence]:
    """Return sender-identity evidence for ``email``."""
    domain = email.from_domain
    evidence: list[Evidence] = []
    if not domain:
        return evidence

    decoded = _decode_punycode(domain) if "xn--" in domain else ""
    # Analyze the visible domain and, when present, the decoded IDN as well so
    # ``xn--pypal-...`` is caught by the same brand logic.
    candidate_domains = [domain]
    if decoded and decoded != domain:
        candidate_domains.append(decoded)

    signals: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for candidate in candidate_domains:
        for signal in _domain_brand_signals(candidate):
            key = (signal["brand"], signal["kind"])
            if key not in seen:
                seen.add(key)
                signals.append(signal)

    display_brands = _display_brands(email.from_display)
    display_mismatch = [
        brand for brand in display_brands if not _is_official(domain, brand)
    ]

    brand_item = _brand_evidence(
        email, signals, display_brands, display_mismatch, decoded
    )
    if brand_item is not None:
        evidence.append(brand_item)

    punycode_item = _punycode_evidence(email, decoded)
    if punycode_item is not None:
        evidence.append(punycode_item)

    free_mail_item = _free_mail_evidence(email, display_brands)
    if free_mail_item is not None:
        evidence.append(free_mail_item)

    return evidence
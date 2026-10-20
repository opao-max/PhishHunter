"""Static URL analysis for phishing triage.

This module is deliberately offline and deterministic: every signal below is
derived from the URL string that is already present in the email.  No DNS or
HTTP request is performed here; reputation and sandbox checks belong to the
tool layer.

The detector aggregates all findings for one target URL into a single
``Evidence`` item so that a short link cannot artificially inflate the score by
producing several near-duplicate records.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlparse

from ..models import EmailMessage, Evidence, Link, host_of, make_evidence

SOURCE = "link_analysis"

SHORTENER_DOMAINS: frozenset[str] = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "rb.gy",
    }
)

SUSPICIOUS_TLDS: frozenset[str] = frozenset(
    {
        "zip",
        "top",
        "xyz",
        "click",
        "live",
        "shop",
        "link",
        "country",
        "gq",
        "tk",
        "ml",
        "cf",
        "work",
    }
)

# Domains that legitimately host a brand's own login/verification pages.
BRAND_DOMAINS: frozenset[str] = frozenset(
    {
        "microsoft.com",
        "microsoftonline.com",
        "office.com",
        "office365.com",
        "outlook.com",
        "live.com",
        "paypal.com",
        "apple.com",
        "icloud.com",
        "google.com",
        "gmail.com",
        "googlemail.com",
        "amazon.com",
        "amazonaws.com",
        "facebook.com",
        "instagram.com",
        "netflix.com",
        "chase.com",
        "wellsfargo.com",
        "bankofamerica.com",
        "dhl.com",
        "fedex.com",
        "ups.com",
        "alipay.com",
        "wechat.com",
        "tencent.com",
        "taobao.com",
        "jd.com",
        "unionpay.com",
        "dropbox.com",
        "linkedin.com",
        "github.com",
    }
)

CREDENTIAL_KEYWORDS = (
    "login",
    "signin",
    "sign-in",
    "logon",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "password",
    "passwd",
    "wallet",
    "recharge",
    "invoice",
    "billing",
    "payment",
    "auth",
    "session",
    "confirm",
    "unlock",
)

_CREDENTIAL_PATH_RE = re.compile(
    r"(?:^|[/?#&=;._-])(?:"
    + "|".join(re.escape(k) for k in CREDENTIAL_KEYWORDS)
    + r")(?![a-z])",
    re.IGNORECASE,
)
_PERCENT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*):")
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

# URLs are rendered into reports; keep a pathological URL from bloating them.
_MAX_URL_DISPLAY = 240

_TITLE_BY_CODE: dict[str, str] = {
    "script_uri": "链接使用脚本或数据 URI",
    "authority_at": "链接使用 @ 混淆真实主机",
    "redirect_ip": "链接跳转至 IP 地址",
    "ip_literal": "链接直接使用 IP 地址",
    "punycode": "链接使用 Punycode 混淆域名",
    "anchor_mismatch": "链接锚文本与实际目标不一致",
    "encoded_url": "链接使用过度百分号编码",
    "redirect": "链接实际跳转到其他域名",
    "shortener": "邮件包含短链接",
    "suspicious_tld": "链接使用高风险顶级域名",
    "credential_path": "链接指向凭据相关页面",
}

_CODE_PRIORITY: tuple[str, ...] = (
    "script_uri",
    "authority_at",
    "redirect_ip",
    "ip_literal",
    "punycode",
    "anchor_mismatch",
    "encoded_url",
    "redirect",
    "shortener",
    "suspicious_tld",
    "credential_path",
)


@dataclass(frozen=True)
class _Finding:
    code: str
    detail: str
    severity: float
    tags: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# public helpers (also reused by the image/QR detector)
# --------------------------------------------------------------------------- #


def effective_scheme(url: str) -> str:
    """Return the literal scheme of *url* without guessing ``http``."""
    match = _SCHEME_RE.match((url or "").strip())
    return match.group(1).lower() if match else ""


def is_ip_host(host: str) -> bool:
    host = (host or "").strip().strip("[]")
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return _IPV4_RE.match(host) is not None


def is_private_host(host: str) -> bool:
    host = (host or "").strip().strip("[]")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
    )


def is_shortener_host(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    return any(host == domain or host.endswith("." + domain) for domain in SHORTENER_DOMAINS)


def is_punycode_host(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    return any(label.startswith("xn--") for label in host.split(".") if label)


def has_suspicious_tld(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if "." not in host:
        return False
    return host.rsplit(".", 1)[-1] in SUSPICIOUS_TLDS


def is_brand_domain(host: str) -> bool:
    host = (host or "").strip().lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    return any(host == domain or host.endswith("." + domain) for domain in BRAND_DOMAINS)


_MULTI_LABEL_SUFFIXES = frozenset(
    {
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.cn", "net.cn", "org.cn", "gov.cn",
        "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
        "co.kr", "or.kr", "com.br", "com.mx", "com.tw", "com.hk",
        "com.sg", "co.nz", "co.za", "co.in", "com.tr", "com.sa", "com.ae",
    }
)


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 using an embedded multi-label suffix table.

    A full Public Suffix List is intentionally not a dependency; this table
    covers the suffixes that matter for the current threat corpus.  The key
    correctness property is that ``evil.co.uk`` and ``bank.co.uk`` are NOT
    treated as the same site.
    """
    labels = [label for label in (host or "").strip(".").lower().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def hosts_related(left: str, right: str) -> bool:
    """True when two hosts are equal or share a registrable domain.

    This prevents ``login.microsoft.com`` versus ``microsoft.com`` from being
    reported as an anchor mismatch while still catching ``paypal.com`` versus
    ``paypal.com.evil.example`` and ``bank.co.uk`` versus ``evil.co.uk``.
    """
    left = (left or "").strip().lower().rstrip(".")
    right = (right or "").strip().lower().rstrip(".")
    if not left or not right:
        return False
    if left == right or left.endswith("." + right) or right.endswith("." + left):
        return True
    return registrable_domain(left) == registrable_domain(right)


def credential_path_keyword(url: str) -> str:
    """Return the credential path/query keyword found in *url*, else ``""``."""
    raw = (url or "").strip()
    if not raw:
        return ""
    candidate = raw if "://" in raw else "http://" + raw
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return ""
    # Check percent-decoded once so ``%6cogin`` is still visible.
    haystack = unquote(parsed.path or "") + "?" + unquote(parsed.query or "")
    match = _CREDENTIAL_PATH_RE.search(haystack)
    return match.group(0).strip("/?#&=;._-") if match else ""


# --------------------------------------------------------------------------- #
# internals
# --------------------------------------------------------------------------- #


def _shorten(value: str, limit: int = _MAX_URL_DISPLAY) -> str:
    value = (value or "").replace("\n", " ").strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _target_host(link: Link) -> str:
    target = link.target
    if effective_scheme(target) in {"javascript", "data", "vbscript", "file"}:
        return ""
    return host_of(target)


def _anchor_host(link: Link) -> str:
    anchor = (link.anchor_text or "").strip()
    if not anchor or len(anchor) > 300:
        return ""
    if any(ch.isspace() for ch in anchor):
        return ""
    if effective_scheme(anchor) in {"javascript", "data", "vbscript", "file", "mailto", "tel"}:
        return effective_scheme(anchor)  # hosts_related will not match
    if "://" not in anchor and "." not in anchor:
        return ""
    return host_of(anchor)


def _authority_has_at(url: str) -> bool:
    candidate = url if "://" in url else "http://" + url
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return False
    return "@" in (parsed.netloc or "")


def _signals_for_link(link: Link) -> list[_Finding]:
    findings: list[_Finding] = []
    target = link.target
    if not target:
        return findings

    scheme = effective_scheme(target)
    original_host = link.original_host if link.original else ""
    target_host = _target_host(link)

    # 1. Scripting / data URIs ------------------------------------------------
    if scheme in {"javascript", "vbscript"}:
        findings.append(
            _Finding(
                "script_uri",
                f"目标以 {scheme}: 开头，点击后会在邮件上下文中执行脚本。",
                0.9,
                ("script_uri",),
            )
        )
    elif scheme == "data":
        findings.append(
            _Finding(
                "script_uri",
                "目标使用 data: URI，可内嵌伪装的 HTML/脚本而不是真实网站。",
                0.88,
                ("script_uri",),
            )
        )
    elif scheme == "file":
        findings.append(
            _Finding(
                "script_uri",
                "目标使用 file: 协议，试图访问本地文件系统。",
                0.82,
                ("script_uri",),
            )
        )

    # 2. Userinfo confusion (``brand.com@attacker.example``) ------------------
    if _authority_has_at(target):
        findings.append(
            _Finding(
                "authority_at",
                f"URL 的 authority 部分包含 @，浏览器真正访问的主机是 {target_host or '未知'}。",
                0.82,
                ("authority_at",),
            )
        )

    # 3. Percent-encoding obfuscation ----------------------------------------
    percent_hits = _PERCENT_RE.findall(target)
    if len(percent_hits) >= 5:
        findings.append(
            _Finding(
                "encoded_url",
                f"URL 含有 {len(percent_hits)} 处百分号编码，疑似用于绕过关键词检测。",
                0.7,
                ("encoded_url",),
            )
        )

    # 4. IP-literal target ----------------------------------------------------
    if target_host and is_ip_host(target_host):
        private = is_private_host(target_host)
        credential = bool(credential_path_keyword(target))
        redirected = bool(link.is_shortened and original_host and original_host != target_host)
        tags: tuple[str, ...] = ("ip_literal",)
        if private or credential or redirected:
            tags = ("ip_literal", "redirect_ip")
            reasons = []
            if redirected:
                reasons.append(f"短链接/原始域名 {original_host} 指向裸 IP")
            if private:
                reasons.append("该 IP 属于私有/保留地址段")
            if credential:
                reasons.append("URL 路径包含凭据采集关键词")
            detail = "；".join(reasons)
            findings.append(
                _Finding(
                    "redirect_ip",
                    f"实际目标为 IP 地址 {target_host}（{detail}），无法通过域名归属核验。",
                    0.84 if private or credential else 0.8,
                    tags,
                )
            )
        else:
            findings.append(
                _Finding(
                    "ip_literal",
                    f"实际目标直接使用 IP 地址 {target_host}，正常业务邮件很少这样链接。",
                    0.75,
                    tags,
                )
            )

    # 5. Known URL shorteners -------------------------------------------------
    shortener_hosts = [h for h in (target_host, original_host) if is_shortener_host(h)]
    if shortener_hosts:
        findings.append(
            _Finding(
                "shortener",
                f"链接使用短链接服务 {shortener_hosts[0]}，真实落地页被隐藏。",
                0.5,
                ("shortener",),
            )
        )

    # 6. Punycode / IDN confusion --------------------------------------------
    punycode_hosts = [h for h in (target_host, original_host) if is_punycode_host(h)]
    if punycode_hosts:
        findings.append(
            _Finding(
                "punycode",
                f"域名 {punycode_hosts[0]} 使用 Punycode（xn--）编码，可能伪装成视觉相似品牌域名。",
                0.78,
                ("punycode",),
            )
        )

    # 7. High-risk TLD --------------------------------------------------------
    suspicious_hosts = [h for h in (target_host, original_host) if has_suspicious_tld(h)]
    if suspicious_hosts:
        tld = suspicious_hosts[0].rsplit(".", 1)[-1]
        findings.append(
            _Finding(
                "suspicious_tld",
                f"域名 {suspicious_hosts[0]} 使用高风险顶级域 .{tld}，钓鱼基础设施占比高。",
                0.5,
                ("suspicious_tld",),
            )
        )

    # 8. Redirect to a different host ----------------------------------------
    if (
        link.resolved
        and original_host
        and target_host
        and original_host != target_host
        and not hosts_related(original_host, target_host)
    ):
        findings.append(
            _Finding(
                "redirect",
                f"声明的原始域名 {original_host} 实际跳转到 {target_host}，二者不属于同一站点。",
                0.62,
                ("redirect",),
            )
        )

    # 9. Credential-harvesting path on a non-brand host ----------------------
    credential = credential_path_keyword(target)
    if credential and target_host and not is_brand_domain(target_host):
        detail = f"路径/参数包含「{credential}」，且目标域名 {target_host} 不属于该品牌自有域名。"
        severity = 0.52
        tags = ("credential_path",)
        if scheme == "http":
            severity = 0.58
            tags = ("credential_path", "plaintext_http")
            detail += " 同时使用明文 HTTP 传输，凭据可能被窃听。"
        findings.append(_Finding("credential_path", detail, severity, tags))

    # 10. Anchor text host versus actual target -------------------------------
    anchor_host = _anchor_host(link)
    if (
        anchor_host
        and target_host
        and anchor_host not in {"javascript", "data", "vbscript", "file", "mailto", "tel"}
        and not hosts_related(anchor_host, target_host)
    ):
        findings.append(
            _Finding(
                "anchor_mismatch",
                f"锚文本显示 {anchor_host}，实际点击后访问 {target_host}，属于典型链接伪装。",
                0.74,
                ("anchor_mismatch",),
            )
        )

    return findings


def _link_key(link: Link) -> str:
    target = (link.target or link.original or "").strip().lower().rstrip("/")
    if not target:
        return ""
    return target


def _merge_findings(records: dict[str, dict[str, object]], link: Link) -> None:
    key = _link_key(link)
    if not key:
        return
    scheme = effective_scheme(link.target or link.original)
    if scheme in {"mailto", "tel", "sms"}:
        return
    record = records.get(key)
    if record is None:
        record = {"link": link, "findings": {}}
        records[key] = record
    bucket = record["findings"]
    assert isinstance(bucket, dict)
    for finding in _signals_for_link(link):
        bucket.setdefault(finding.code, finding)


def _build_evidence(link: Link, findings: list[_Finding]) -> Evidence:
    codes = [item.code for item in findings]
    primary_code = next((code for code in _CODE_PRIORITY if code in codes), codes[0])
    title = _TITLE_BY_CODE.get(primary_code, "链接存在可疑特征")

    target = link.target or link.original
    target_host = _target_host(link)
    parts: list[str] = []
    if link.original and link.original != target:
        parts.append(f"原始链接：{_shorten(link.original)}")
        parts.append(f"实际目标：{_shorten(target)}")
    else:
        parts.append(f"链接：{_shorten(target)}")
    if target_host:
        parts.append(f"目标主机：{target_host}")
    detail = "；".join(parts) + "。发现：" + "；".join(
        f"{index}) {item.detail}" for index, item in enumerate(findings, start=1)
    )

    severity = min(0.97, max(item.severity for item in findings) + 0.02 * (len(findings) - 1))
    tags: list[str] = []
    for item in findings:
        for tag in item.tags:
            if tag not in tags:
                tags.append(tag)
    return make_evidence(
        "url",
        title,
        detail,
        severity,
        confidence=0.9,
        source=SOURCE,
        tags=tags,
        raw={
            "url": target,
            "original": link.original,
            "host": target_host,
            "original_host": link.original_host,
            "signals": codes,
        },
    )


# --------------------------------------------------------------------------- #
# detector entry point
# --------------------------------------------------------------------------- #


def analyze_links(email: EmailMessage) -> list[Evidence]:
    """Return one aggregated evidence item per distinct suspicious URL."""
    if not email.links:
        return []

    records: dict[str, dict[str, object]] = {}
    for link in email.links:
        _merge_findings(records, link)

    evidence: list[Evidence] = []
    for record in records.values():
        bucket = record["findings"]
        if not isinstance(bucket, dict) or not bucket:
            continue
        ordered = sorted(
            bucket.values(),
            key=lambda item: (_CODE_PRIORITY.index(item.code), -item.severity),
        )
        evidence.append(_build_evidence(record["link"], ordered))  # type: ignore[arg-type]
    return evidence
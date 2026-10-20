"""Image / QR forensics tool.

The tool reasons over metadata that an upstream OCR/QR pipeline already
extracted (``ocr_text`` and ``qr_payload``).  When raw image bytes are provided
as ``content_b64`` and OpenCV is installed, it can also decode the QR code
locally in memory.  It never contacts the URL embedded in a QR code.

Signals produced:

* QR destination is an IP literal, shortener, punycode host, suspicious TLD or
  a credential-collection path  -> ``qr_payload``
* OCR text contains credential or urgency language -> content evidence
* OCR text names a brand that does not own the QR destination -> ``brand_spoof``
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from ..models import Evidence, ToolResult, clean_url, make_evidence, split_markdown_link
from .base import BaseTool
from .intel import is_ip_literal, require_text_param, url_host

SHORTENER_DOMAINS = {
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

SUSPICIOUS_TLDS = {
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

_CREDENTIAL_PATH_RE = re.compile(
    r"(?:^|[/?&=._\-])(?:login|signin|sign-in|verify|secure|account|update|"
    r"password|wallet|recharge|invoice)(?:$|[/?&=._\-])",
    re.IGNORECASE,
)

_CREDENTIAL_WORDS = (
    "password",
    "passcode",
    "login",
    "sign in",
    "signin",
    "verify",
    "verification",
    "credential",
    "otp",
    "one-time",
    "account",
    "密码",
    "登录",
    "验证",
    "账号",
    "口令",
)

_URGENCY_WORDS = (
    "urgent",
    "immediately",
    "immediate",
    "expire",
    "expires",
    "expired",
    "locked",
    "suspend",
    "suspended",
    "final warning",
    "紧急",
    "立即",
    "马上",
    "过期",
    "冻结",
    "停用",
    "最后警告",
)

# Brand aliases are used only to spot a brand mentioned in OCR text.
BRAND_ALIASES: dict[str, tuple[str, ...]] = {
    "microsoft": ("microsoft", "微软", "office 365"),
    "paypal": ("paypal", "贝宝"),
    "apple": ("apple", "icloud", "苹果"),
    "amazon": ("amazon", "亚马逊"),
    "google": ("google", "gmail", "谷歌"),
    "netflix": ("netflix", "奈飞"),
    "facebook": ("facebook", "脸书"),
    "instagram": ("instagram",),
    "dhl": ("dhl",),
    "fedex": ("fedex",),
    "ups": ("ups",),
    "alipay": ("alipay", "支付宝"),
    "wechat": ("wechat", "weixin", "微信"),
    "tencent": ("tencent", "腾讯"),
    "taobao": ("taobao", "淘宝"),
    "jd": ("jd.com", "京东"),
    "unionpay": ("unionpay", "银联"),
    "chase": ("chase",),
    "wellsfargo": ("wellsfargo",),
}

# Only the brand's own registered domains are considered legitimate.
BRAND_DOMAINS: dict[str, tuple[str, ...]] = {
    "microsoft": (
        "microsoft.com",
        "live.com",
        "office.com",
        "office365.com",
        "outlook.com",
    ),
    "paypal": ("paypal.com", "paypal.me"),
    "apple": ("apple.com", "icloud.com"),
    "amazon": ("amazon.com", "amazon.cn"),
    "google": ("google.com", "gmail.com", "googleusercontent.com"),
    "netflix": ("netflix.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "dhl": ("dhl.com",),
    "fedex": ("fedex.com",),
    "ups": ("ups.com",),
    "alipay": ("alipay.com",),
    "wechat": ("wechat.com", "weixin.qq.com", "qq.com"),
    "tencent": ("tencent.com", "qq.com"),
    "taobao": ("taobao.com", "tmall.com"),
    "jd": ("jd.com",),
    "unionpay": ("unionpay.com", "unionpayintl.com"),
    "chase": ("chase.com",),
    "wellsfargo": ("wellsfargo.com",),
}


# --------------------------------------------------------------------------- #
# pure helpers
# --------------------------------------------------------------------------- #


def extract_qr_url(payload: str) -> str:
    """Turn a raw QR payload into a URL suitable for host/path inspection."""
    text = str(payload or "").strip()
    if not text:
        return ""
    unwrapped, _anchor = split_markdown_link(text)
    text = clean_url(unwrapped).strip().strip("<>[]()'\"“”‘’")
    if not text:
        return ""
    if not re.match(r"^[a-z][a-z0-9+.-]*://", text, re.IGNORECASE):
        scheme = re.match(r"^([a-z][a-z0-9+.-]*):", text, re.IGNORECASE)
        if scheme and scheme.group(1).lower() not in {"http", "https"}:
            # Non-web schemes (javascript:, data:, tel:) have no host; keep
            # them intact for reporting, do not invent a host.
            return text
        text = "http://" + text.lstrip("/")
    return text


def qr_risk_reasons(qr_url: str) -> list[str]:
    """Explain why a QR destination is high risk (empty list when benign)."""
    if not qr_url:
        return []
    host = url_host(qr_url)
    if not host:
        return []
    reasons: list[str] = []
    if is_ip_literal(host):
        reasons.append("主机为 IP 地址")
    if any(host == item or host.endswith("." + item) for item in SHORTENER_DOMAINS):
        reasons.append("使用短链接服务")
    if any(label.startswith("xn--") for label in host.split(".")):
        reasons.append("使用 Punycode 混淆")
    if "." in host:
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            reasons.append(f"使用可疑顶级域 .{tld}")
    try:
        parsed = urlparse(qr_url)
    except ValueError:
        parsed = None
    if parsed is not None:
        path_query = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
        if _CREDENTIAL_PATH_RE.search(path_query):
            reasons.append("路径包含凭据采集关键词")
    return reasons


def ocr_flags(ocr_text: str) -> tuple[list[str], dict[str, list[str]]]:
    """Return flag names and the matched words that justify them."""
    lowered = str(ocr_text or "").lower()
    credential_hits = [word for word in _CREDENTIAL_WORDS if word in lowered]
    urgency_hits = [word for word in _URGENCY_WORDS if word in lowered]
    flags: list[str] = []
    hits: dict[str, list[str]] = {}
    if credential_hits:
        flags.append("credential_language")
        hits["credential_language"] = credential_hits[:6]
    if urgency_hits:
        flags.append("urgency")
        hits["urgency"] = urgency_hits[:6]
    return flags, hits


def _contains_alias(text: str, alias: str) -> bool:
    alias = alias.lower().strip()
    if not alias:
        return False
    if alias.isascii() and alias[0].isalnum():
        return re.search(
            rf"(?<![a-z0-9]){re.escape(alias)}(?![a-z0-9])", text
        ) is not None
    return alias in text


def brands_in_text(text: str) -> list[str]:
    lowered = str(text or "").lower()
    found: list[str] = []
    for brand, aliases in BRAND_ALIASES.items():
        if any(_contains_alias(lowered, alias) for alias in aliases):
            found.append(brand)
    return found


def _host_matches_brand(host: str, brand: str) -> bool:
    host = (host or "").lower().rstrip(".")
    if not host:
        return False
    return any(
        host == domain or host.endswith("." + domain)
        for domain in BRAND_DOMAINS.get(brand, ())
    )


def brand_conflict(ocr_text: str, qr_host: str) -> tuple[bool, list[str]]:
    """A brand is named in the image but does not own the QR destination."""
    brands = brands_in_text(ocr_text)
    if not brands or not qr_host:
        return False, brands
    for brand in brands:
        if not _host_matches_brand(qr_host, brand):
            return True, brands
    return False, brands


# --------------------------------------------------------------------------- #
# tool
# --------------------------------------------------------------------------- #


class ImageForensicsTool(BaseTool):
    name = "image_forensics"
    description = (
        "分析图片的 OCR 文本、二维码载荷与品牌一致性，识别二维码钓鱼（支持可选本地 QR 解码）。"
    )
    input_schema: dict[str, Any] = {
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": "图片文件名，例如 qr-code.png",
                "minLength": 1,
            },
            "ocr_text": {
                "type": "string",
                "description": "上游 OCR 提取的图片文本（可选）",
            },
            "qr_payload": {
                "type": "string",
                "description": "上游二维码解码得到的载荷（可选）",
            },
            "content_b64": {
                "type": "string",
                "description": "图片原始字节的 base64（可选；安装 OpenCV 时可本地解码二维码）",
            },
        },
        "required": ["filename"],
        "additionalProperties": False,
    }

    def __init__(self) -> None:
        # No provider: all analysis is local metadata reasoning.
        pass

    def run(self, params: dict[str, Any]) -> ToolResult:
        filename = require_text_param(params, "filename", self.name)
        ocr_text = params.get("ocr_text")
        ocr_text = ocr_text if isinstance(ocr_text, str) else ""
        payload = params.get("qr_payload")
        payload = payload if isinstance(payload, str) else ""
        if not payload:
            content_b64 = params.get("content_b64")
            if isinstance(content_b64, str) and content_b64:
                try:
                    from ..detectors.image_analysis import decode_qr_from_b64

                    payload = decode_qr_from_b64(content_b64)
                except Exception:  # noqa: BLE001 - optional decoding capability
                    payload = ""

        qr_url = extract_qr_url(payload)
        qr_host = url_host(qr_url)
        reasons = qr_risk_reasons(qr_url)
        flags, hits = ocr_flags(ocr_text)
        conflict, brands = brand_conflict(ocr_text, qr_host)

        evidence: list[Evidence] = []
        if reasons:
            evidence.append(
                make_evidence(
                    "image",
                    "二维码载荷指向高风险地址",
                    f"图片 {filename} 的二维码指向 {qr_url}"
                    + (f"（主机 {qr_host}）" if qr_host else "")
                    + "，风险原因："
                    + "；".join(reasons)
                    + "。",
                    0.9,
                    0.92,
                    source=f"tool:{self.name}",
                    tags=["qr_payload"],
                    raw={"filename": filename, "qr_url": qr_url, "reasons": reasons},
                )
            )

        if flags:
            matched = "；".join(
                f"{name}: {'、'.join(words)}" for name, words in hits.items()
            )
            evidence.append(
                make_evidence(
                    "content",
                    "图片 OCR 文本包含敏感诱导话术",
                    f"图片 {filename} 的 OCR 文本命中 {matched}。",
                    0.5,
                    0.75,
                    source=f"tool:{self.name}",
                    tags=flags,
                    raw={"filename": filename, "ocr_flags": flags, "hits": hits},
                )
            )

        if conflict:
            evidence.append(
                make_evidence(
                    "image",
                    "图片品牌与二维码落地域名不一致",
                    f"图片 {filename} 的 OCR 文本提到品牌"
                    f"「{'、'.join(brands)}」，但二维码落地域名为 "
                    f"{qr_host}，并非该品牌官方域名。",
                    0.75,
                    0.8,
                    source=f"tool:{self.name}",
                    tags=["brand_spoof"],
                    raw={
                        "filename": filename,
                        "brands": brands,
                        "qr_host": qr_host,
                    },
                )
            )

        data = {
            "found": bool(qr_url or ocr_text.strip()),
            "qr_url": qr_url,
            "qr_host": qr_host,
            "ocr_flags": flags,
            "brand_conflict": conflict,
        }
        return ToolResult(tool=self.name, ok=True, data=data, evidence=evidence)
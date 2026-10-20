"""Image and QR-code analysis.

The prototype consumes metadata that an upstream OCR/QR pipeline would provide
(``ocr_text``, ``qr_payload``, ``detected_brands``).  When raw image bytes are
supplied as ``content_b64`` *and* OpenCV is available, it also performs real
in-memory QR decoding (no file I/O, no network).  OCR remains metadata-driven.
"""

from __future__ import annotations

import base64
import re

from ..models import EmailMessage, Evidence, ImageAsset, clean_url, host_of, make_evidence
from .link_analysis import (
    credential_path_keyword,
    effective_scheme,
    has_suspicious_tld,
    is_ip_host,
    is_punycode_host,
    is_shortener_host,
)

SOURCE = "image_analysis"

_URL_IN_TEXT_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
_BARE_HOST_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}(?::\d{1,5})?(?:[/?#].*)?$",
    re.IGNORECASE,
)
_IP_PAYLOAD_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?(?:[/?#].*)?$")

_CREDENTIAL_OCR_RE = re.compile(
    r"(password|passcode|passwd|otp|one[\s-]?time|login|log\s*in|sign\s*in|"
    r"verify|verification|credential|account|unlock|billing|"
    r"密码|口令|验证码|登录|账号|账户|验证|解锁)",
    re.IGNORECASE,
)
_URGENCY_OCR_RE = re.compile(
    r"(urgent|immediately|right now|within\s+\d+\s*(?:hours?|minutes?)|expir\w*|"
    r"suspend\w*|locked|final warning|act now|"
    r"紧急|立即|马上|小时|分钟|即将|冻结|锁定|过期|失效|最后警告)",
    re.IGNORECASE,
)

_QR_TITLE = "二维码指向高风险地址"
_QR_SEVERITY = {
    "ip": 0.9,
    "punycode": 0.88,
    "shortener": 0.82,
    "suspicious_tld": 0.78,
    "credential_path": 0.8,
    "script_uri": 0.9,
}

_BRAND_DOMAINS: dict[str, frozenset[str]] = {
    "microsoft": frozenset(
        {"microsoft.com", "microsoftonline.com", "office.com", "office365.com",
         "outlook.com", "live.com"}
    ),
    "office365": frozenset({"office.com", "office365.com", "microsoft.com"}),
    "outlook": frozenset({"outlook.com", "microsoft.com", "live.com"}),
    "paypal": frozenset({"paypal.com"}),
    "apple": frozenset({"apple.com", "icloud.com"}),
    "icloud": frozenset({"icloud.com", "apple.com"}),
    "google": frozenset({"google.com", "gmail.com", "googlemail.com"}),
    "gmail": frozenset({"gmail.com", "google.com"}),
    "amazon": frozenset({"amazon.com", "amazonaws.com"}),
    "facebook": frozenset({"facebook.com"}),
    "instagram": frozenset({"instagram.com"}),
    "netflix": frozenset({"netflix.com"}),
    "chase": frozenset({"chase.com"}),
    "wellsfargo": frozenset({"wellsfargo.com"}),
    "dhl": frozenset({"dhl.com"}),
    "fedex": frozenset({"fedex.com"}),
    "ups": frozenset({"ups.com"}),
    "alipay": frozenset({"alipay.com"}),
    "wechat": frozenset({"wechat.com", "weixin.qq.com"}),
    "tencent": frozenset({"tencent.com", "qq.com", "weixin.qq.com"}),
    "taobao": frozenset({"taobao.com"}),
    "jd": frozenset({"jd.com"}),
    "unionpay": frozenset({"unionpay.com"}),
}


def _shorten(value: str, limit: int = 220) -> str:
    value = (value or "").replace("\n", " ").strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def decode_qr_from_b64(content_b64: str, max_bytes: int = 5_000_000) -> str:
    """Decode a QR payload from base64 image bytes, if OpenCV is installed.

    Returns ``""`` on any failure (missing dependency, invalid image, no QR).
    The image is decoded in memory and never written to disk or fetched.
    """
    if not content_b64:
        return ""
    try:  # optional dependency; the rest of the detector stays stdlib-only
        import cv2  # type: ignore
        import numpy as np  # type: ignore
    except Exception:  # noqa: BLE001 - optional capability
        return ""
    try:
        raw = base64.b64decode(content_b64, validate=False)
    except (ValueError, TypeError):
        return ""
    if not raw or len(raw) > max_bytes:
        return ""
    try:
        buffer = np.frombuffer(raw, dtype=np.uint8)
        image = cv2.imdecode(buffer, cv2.IMREAD_COLOR)
        if image is None:
            return ""
        # Tiny QR matrices (e.g. 29x29 from an encoder) are below OpenCV's
        # detector threshold; upscale with nearest-neighbour first.
        height, width = image.shape[:2]
        if min(height, width) < 100:
            scale = max(4, int(160 / max(1, min(height, width))))
            image = cv2.resize(
                image, None, fx=scale, fy=scale, interpolation=cv2.INTER_NEAREST
            )
        detector = cv2.QRCodeDetector()
        data, _points, _straight = detector.detectAndDecode(image)
        if not data:
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            data, _points, _straight = detector.detectAndDecode(gray)
        return str(data or "").strip()
    except Exception:  # noqa: BLE001 - malformed image must not break triage
        return ""


def _extract_url(payload: str) -> str:
    """Extract the first URL from a QR payload, accepting bare hosts."""
    payload = (payload or "").strip()
    if not payload:
        return ""
    first_token = payload.split()[0].strip().strip("<>\"'")
    if effective_scheme(first_token) in {"javascript", "data", "vbscript", "file"}:
        return clean_url(first_token)
    match = _URL_IN_TEXT_RE.search(payload)
    if match:
        return clean_url(match.group(0))
    token = first_token
    if _IP_PAYLOAD_RE.match(token) or _BARE_HOST_RE.match(token):
        return clean_url(token)
    return ""


def _payload_hosts(url: str) -> tuple[str, str]:
    """Return ``(host, scheme)`` for a QR URL without assuming HTTP."""
    scheme = effective_scheme(url)
    if scheme in {"javascript", "data", "vbscript", "file"}:
        return "", scheme
    return host_of(url), scheme


def _qr_signals(url: str) -> list[tuple[str, str]]:
    """Return ``(code, Chinese detail)`` signals for a QR payload URL."""
    host, scheme = _payload_hosts(url)
    signals: list[tuple[str, str]] = []

    if scheme in {"javascript", "data", "vbscript", "file"}:
        signals.append((f"script_uri:{scheme}", f"二维码包含 {scheme}: URI，可直接执行脚本"))
        return signals

    if not host:
        return signals

    if is_ip_host(host):
        signals.append(("ip", f"二维码目标直接使用 IP 地址 {host}"))
    if is_shortener_host(host):
        signals.append(("shortener", f"二维码使用短链接服务 {host}，落地页被隐藏"))
    if is_punycode_host(host):
        signals.append(("punycode", f"二维码域名 {host} 使用 Punycode 混淆"))
    if has_suspicious_tld(host):
        signals.append(
            ("suspicious_tld", f"二维码域名 {host} 使用高风险顶级域 .{host.rsplit('.', 1)[-1]}")
        )
    keyword = credential_path_keyword(url)
    if keyword:
        suffix = "" if is_ip_host(host) else f"（域名 {host}）"
        signals.append(
            ("credential_path", f"二维码链接路径包含凭据关键词「{keyword}」{suffix}")
        )
    return signals


def _dedupe_images(email: EmailMessage) -> list[ImageAsset]:
    images: list[ImageAsset] = list(email.images)
    for attachment in email.attachments:
        if attachment.is_image:
            images.append(
                ImageAsset(
                    filename=attachment.filename,
                    hash=attachment.hash,
                    mime_type=attachment.mime_type,
                )
            )
    seen: set[tuple[str, str, str, str]] = set()
    result: list[ImageAsset] = []
    for image in images:
        key = (
            (image.filename or "").strip().lower(),
            (image.hash or "").strip().lower(),
            image.qr_payload.strip(),
            image.ocr_text.strip(),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(image)
    return result


def _brand_owned(brand: str, sender_domain: str) -> bool:
    """Whether *sender_domain* legitimately belongs to *brand*."""
    brand_key = (brand or "").strip().lower().replace(" ", "")
    if not brand_key or not sender_domain:
        return True
    # Logos are often labelled "Microsoft Corporation" or "Microsoft 365";
    # resolve the label to a known brand before comparing domains.
    known = next((key for key in _BRAND_DOMAINS if key in brand_key), "")
    domains = _BRAND_DOMAINS.get(known)
    if domains is None:
        # Unknown brand label: fall back to a raw token comparison.
        return brand_key in sender_domain or sender_domain in brand_key
    domain = sender_domain.lower().rstrip(".")
    return any(domain == item or domain.endswith("." + item) for item in domains)


def analyze_images(email: EmailMessage) -> list[Evidence]:
    """Analyse QR payloads, OCR text and brand logos in email imagery."""
    images = _dedupe_images(email)
    if not images:
        return []

    evidence: list[Evidence] = []
    seen_qr: set[str] = set()
    sender_domain = email.from_domain

    for image in images:
        filename = image.filename or "(未命名图片)"

        # -- QR payload ---------------------------------------------------- #
        payload = (image.qr_payload or "").strip()
        decoded_from_image = False
        if not payload and image.content_b64:
            payload = decode_qr_from_b64(image.content_b64)
            decoded_from_image = bool(payload)
        if payload:
            url = _extract_url(payload)
            if url:
                signals = _qr_signals(url)
                qr_key = url.lower().rstrip("/")
                if signals and qr_key not in seen_qr:
                    seen_qr.add(qr_key)
                    codes = [code.split(":", 1)[0] for code, _ in signals]
                    severity = min(
                        0.96,
                        max(_QR_SEVERITY.get(code, 0.78) for code in codes)
                        + 0.02 * (len(signals) - 1),
                    )
                    host, _ = _payload_hosts(url)
                    evidence.append(
                        make_evidence(
                            "image",
                            _QR_TITLE,
                            f"图片 {filename} 的二维码载荷：{_shorten(url)}。发现："
                            + "；".join(
                                f"{index}) {detail}"
                                for index, (_, detail) in enumerate(signals, start=1)
                            ),
                            severity,
                            confidence=0.9,
                            source=SOURCE,
                            tags=["qr_payload", *codes],
                            raw={
                                "image": filename,
                                "qr_payload": payload,
                                "url": url,
                                "host": host,
                                "signals": codes,
                                "decoded_from_image": decoded_from_image,
                            },
                        )
                    )

        # -- OCR text ------------------------------------------------------ #
        ocr = (image.ocr_text or "").strip()
        if ocr:
            credential = _CREDENTIAL_OCR_RE.search(ocr)
            urgency = _URGENCY_OCR_RE.search(ocr)
            if credential or urgency:
                matched: list[str] = []
                tags: list[str] = []
                if credential:
                    matched.append(f"凭据/账户词「{credential.group(0)}」")
                    tags.append("credential_language")
                if urgency:
                    matched.append(f"紧迫/威胁词「{urgency.group(0)}」")
                    tags.append("urgency")
                severity = 0.5 if credential and urgency else 0.42
                evidence.append(
                    make_evidence(
                        "content",
                        "图片 OCR 文本包含凭据或紧迫诱导",
                        f"图片 {filename} 的 OCR 文本命中"
                        + "、".join(matched)
                        + f"；文本片段：{_shorten(ocr)}",
                        severity,
                        confidence=0.7,
                        source=SOURCE,
                        tags=tags,
                        raw={
                            "image": filename,
                            "credential": bool(credential),
                            "urgency": bool(urgency),
                        },
                    )
                )

        # -- Brand logo versus sender domain ------------------------------- #
        conflicts = [
            brand
            for brand in (image.detected_brands or [])
            if brand and sender_domain and not _brand_owned(brand, sender_domain)
        ]
        if conflicts:
            brands = "、".join(conflicts)
            evidence.append(
                make_evidence(
                    "image",
                    "图片品牌标识与发件域不一致",
                    f"图片 {filename} 检测到品牌「{brands}」，但发件域名为 "
                    f"{sender_domain}，不属于该品牌自有域名。",
                    0.72,
                    confidence=0.82,
                    source=SOURCE,
                    tags=["brand_spoof", "brand_mismatch"],
                    raw={
                        "image": filename,
                        "brands": conflicts,
                        "sender_domain": sender_domain,
                    },
                )
            )

    return evidence
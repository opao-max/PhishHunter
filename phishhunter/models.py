"""Shared data models for PhishHunter.

Everything in this module is dependency-free (standard library only) so the
detectors, tools, LLM layer and report renderers can all agree on one contract.
"""

from __future__ import annotations

import os
import html
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return low
    return max(low, min(high, value))


_MD_LINK_RE = re.compile(r"^\s*\[([^\]]{0,300})\]\(\s*([^)\s]+)\s*\)\s*$")
_BODY_MD_RE = re.compile(r"\[([^\]]{0,300})\]\(\s*([^)\s]+)\s*\)")
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_HTML_ANCHOR_RE = re.compile(
    r"<a\b[^>]*?\bhref\s*=\s*(?:\"([^\"]*)\"|'([^']*)')[^>]*>(.*?)</a\s*>",
    re.IGNORECASE | re.DOTALL,
)
_HTML_SRC_RE = re.compile(
    r"\b(?:src|href)\s*=\s*(?:\"([^\"]*)\"|'([^']*)')", re.IGNORECASE
)
_TAG_RE = re.compile(r"<[^>]+>")


def split_markdown_link(value: str) -> tuple[str, str]:
    """Return ``(url, anchor_text)`` for both markdown and plain values."""
    value = (value or "").strip()
    m = _MD_LINK_RE.match(value)
    if m:
        return m.group(2).strip(), m.group(1).strip()
    return value, ""


def clean_url(url: str) -> str:
    url = (url or "").strip().strip("<>")
    # Strip punctuation that commonly trails a URL in prose.
    while url and url[-1] in ".,;:!?)]}'\"”’":
        url = url[:-1]
    return url


def host_of(url: str) -> str:
    url = clean_url(url)
    if not url:
        return ""
    if "://" not in url:
        url = "http://" + url
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""
    return host.rstrip(".")


def _url_key(url: str) -> str:
    return clean_url(url).rstrip("/").lower()


# --------------------------------------------------------------------------- #
# email input model
# --------------------------------------------------------------------------- #


@dataclass
class Link:
    original: str = ""
    resolved: str = ""
    anchor_text: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "Link":
        if isinstance(data, str):
            url, anchor = split_markdown_link(data)
            return cls(original=clean_url(url), anchor_text=anchor)
        if not isinstance(data, dict):
            return cls(original=str(data or ""))

        raw_original = str(
            data.get("original") or data.get("url") or data.get("href") or ""
        )
        original, md_anchor = split_markdown_link(raw_original)
        anchor = str(data.get("anchor_text") or data.get("text") or md_anchor or "")

        raw_resolved = str(
            data.get("resolved")
            or data.get("final_url")
            or data.get("target")
            or data.get("redirect")
            or ""
        )
        resolved, _ = split_markdown_link(raw_resolved)
        return cls(
            original=clean_url(original),
            resolved=clean_url(resolved),
            anchor_text=anchor.strip(),
        )

    @property
    def target(self) -> str:
        """The URL that will actually be opened."""
        return self.resolved or self.original

    @property
    def host(self) -> str:
        return host_of(self.target)

    @property
    def original_host(self) -> str:
        return host_of(self.original)

    @property
    def is_shortened(self) -> bool:
        return bool(
            self.resolved
            and self.original_host
            and self.host
            and self.original_host != self.host
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Attachment:
    filename: str = ""
    hash: str = ""
    size_bytes: int | None = None
    mime_type: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "Attachment":
        if isinstance(data, str):
            return cls(filename=str(data))
        if not isinstance(data, dict):
            return cls(filename=str(data or ""))
        size = data.get("size_bytes", data.get("size"))
        try:
            size = int(size) if size is not None else None
        except (TypeError, ValueError):
            size = None
        return cls(
            filename=str(data.get("filename") or data.get("name") or ""),
            hash=str(data.get("hash") or data.get("sha256") or "").strip(),
            size_bytes=size,
            mime_type=str(data.get("mime_type") or data.get("content_type") or ""),
        )

    @property
    def extension(self) -> str:
        return os.path.splitext(self.filename.lower())[1]

    @property
    def extensions(self) -> list[str]:
        """All suffixes, e.g. ``invoice.pdf.exe`` -> [".pdf", ".exe"]."""
        return re.findall(r"\.[A-Za-z0-9]{1,8}", self.filename.lower())

    @property
    def has_double_extension(self) -> bool:
        exts = self.extensions
        return len(exts) >= 2 and exts[-1] in {
            ".exe",
            ".scr",
            ".js",
            ".jse",
            ".vbs",
            ".vbe",
            ".bat",
            ".cmd",
            ".com",
            ".pif",
            ".lnk",
            ".hta",
            ".ps1",
            ".msi",
            ".jar",
        }

    @property
    def is_executable(self) -> bool:
        return self.extension in {
            ".exe",
            ".scr",
            ".js",
            ".jse",
            ".vbs",
            ".vbe",
            ".bat",
            ".cmd",
            ".com",
            ".pif",
            ".lnk",
            ".hta",
            ".ps1",
            ".msi",
            ".jar",
            ".iso",
            ".img",
        }

    @property
    def is_archive(self) -> bool:
        return self.extension in {
            ".zip",
            ".rar",
            ".7z",
            ".tar",
            ".gz",
            ".tgz",
            ".bz2",
            ".xz",
            ".cab",
            ".iso",
        }

    @property
    def is_macro_document(self) -> bool:
        return self.extension in {".docm", ".xlsm", ".pptm", ".dotm", ".xlam"}

    @property
    def is_image(self) -> bool:
        return self.extension in {
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".bmp",
            ".webp",
            ".svg",
            ".tif",
            ".tiff",
        }

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ImageAsset:
    filename: str = ""
    hash: str = ""
    mime_type: str = ""
    ocr_text: str = ""
    qr_payload: str = ""
    detected_brands: list[str] = field(default_factory=list)
    alt_text: str = ""
    content_b64: str = ""

    @classmethod
    def from_dict(cls, data: Any) -> "ImageAsset":
        if isinstance(data, str):
            return cls(filename=data)
        if not isinstance(data, dict):
            return cls(filename=str(data or ""))
        brands = data.get("detected_brands") or data.get("brands") or []
        if isinstance(brands, str):
            brands = [brands]
        return cls(
            filename=str(data.get("filename") or data.get("name") or ""),
            hash=str(data.get("hash") or data.get("sha256") or "").strip(),
            mime_type=str(data.get("mime_type") or ""),
            ocr_text=str(data.get("ocr_text") or data.get("text") or ""),
            qr_payload=str(data.get("qr_payload") or data.get("qr") or ""),
            detected_brands=[str(b) for b in brands],
            alt_text=str(data.get("alt_text") or data.get("alt") or ""),
            content_b64=str(data.get("content_b64") or data.get("data") or ""),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EmailMessage:
    id: str = "email_unknown"
    headers: dict[str, str] = field(default_factory=dict)
    body_text: str = ""
    body_html: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    images: list[ImageAsset] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EmailMessage":
        data = data or {}
        raw_headers = data.get("headers") or {}
        headers: dict[str, str] = {}
        if isinstance(raw_headers, dict):
            for key, value in raw_headers.items():
                if isinstance(value, (list, tuple)):
                    value = "; ".join(str(v) for v in value)
                headers[str(key).strip().lower()] = str(value).strip()

        body_text = str(data.get("body_text") or data.get("body") or "")
        body_html = str(data.get("body_html") or data.get("html") or "")

        links: list[Link] = []
        for item in data.get("links") or []:
            link = Link.from_dict(item)
            if link.original or link.resolved:
                links.append(link)

        # Supplement declared links with URLs found in the plain-text body.
        seen = {_url_key(link.original) for link in links}
        seen |= {_url_key(link.resolved) for link in links if link.resolved}
        candidates: list[tuple[str, str]] = []
        for anchor, url in _BODY_MD_RE.findall(body_text):
            candidates.append((url, anchor))
        # Remove markdown links before the plain-URL sweep, otherwise the
        # ``](...)`` bridge produces a bogus second URL.
        body_without_md = _BODY_MD_RE.sub(" ", body_text)
        for url in _URL_RE.findall(body_without_md):
            candidates.append((url, ""))
        for url, anchor in candidates:
            url = clean_url(url)
            if not url or _url_key(url) in seen:
                continue
            links.append(Link(original=url, anchor_text=anchor.strip()))
            seen.add(_url_key(url))

        # HTML-only emails are common; the declared ``links`` array may be
        # absent while the hidden/malicious URL lives in an href/src attribute.
        html_candidates: list[tuple[str, str]] = []
        for match in _HTML_ANCHOR_RE.finditer(body_html):
            href = match.group(1) if match.group(1) is not None else match.group(2) or ""
            anchor = _TAG_RE.sub(" ", match.group(3) or "")
            html_candidates.append((href, anchor))
        for match in _HTML_SRC_RE.finditer(body_html):
            value = match.group(1) if match.group(1) is not None else match.group(2) or ""
            html_candidates.append((value, ""))
        for raw_url, anchor in html_candidates:
            url = clean_url(html.unescape(raw_url))
            if not url or url.startswith("#"):
                continue
            if url.startswith("//"):
                url = "http:" + url
            if _url_key(url) in seen:
                continue
            links.append(Link(original=url, anchor_text=anchor.strip()))
            seen.add(_url_key(url))

        attachments = [
            Attachment.from_dict(item) for item in (data.get("attachments") or [])
        ]
        image_items = data.get("images") or data.get("inline_images") or []
        images = [ImageAsset.from_dict(item) for item in image_items]

        return cls(
            id=str(data.get("id") or data.get("email_id") or "email_unknown"),
            headers=headers,
            body_text=body_text,
            body_html=body_html,
            links=links,
            attachments=attachments,
            images=images,
            raw=data,
        )

    # -- header helpers ---------------------------------------------------- #

    def header(self, name: str, default: str = "") -> str:
        return self.headers.get(name.lower().strip(), default)

    @property
    def subject(self) -> str:
        return self.header("subject")

    @property
    def sender_raw(self) -> str:
        return self.header("from")

    @property
    def from_display(self) -> str:
        display, _ = parseaddr(self.sender_raw)
        return display.strip().strip('"')

    @property
    def from_address(self) -> str:
        _, address = parseaddr(self.sender_raw)
        if not address and "@" in self.sender_raw:
            address = self.sender_raw.strip().strip("<>")
        return address.strip().lower()

    @property
    def from_domain(self) -> str:
        return self.from_address.rsplit("@", 1)[-1] if "@" in self.from_address else ""

    @property
    def reply_to_raw(self) -> str:
        return self.header("reply-to")

    @property
    def reply_to_address(self) -> str:
        _, address = parseaddr(self.reply_to_raw)
        return address.strip().lower()

    @property
    def reply_to_domain(self) -> str:
        address = self.reply_to_address
        return address.rsplit("@", 1)[-1] if "@" in address else ""

    @property
    def return_path(self) -> str:
        return self.header("return-path")

    @property
    def to_address(self) -> str:
        return self.header("to")

    def auth_result(self, mechanism: str) -> str:
        """SPF/DKIM/DMARC result, explicit header first, then Authentication-Results."""
        mechanism = mechanism.lower()
        explicit = self.header(f"{mechanism}_result").strip().lower()
        if explicit:
            return explicit
        auth = self.header("authentication-results")
        m = re.search(rf"\b{re.escape(mechanism)}\s*=\s*([A-Za-z]+)", auth)
        return m.group(1).lower() if m else ""

    @property
    def auth_summary(self) -> dict[str, str]:
        return {m: self.auth_result(m) for m in ("spf", "dkim", "dmarc")}

    @property
    def text_for_analysis(self) -> str:
        return "\n".join(x for x in (self.subject, self.body_text) if x)

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        data = asdict(self)
        if not include_raw:
            data.pop("raw", None)
        return data


# --------------------------------------------------------------------------- #
# evidence / analysis models
# --------------------------------------------------------------------------- #

CATEGORIES = (
    "header_auth",
    "sender_identity",
    "url",
    "attachment",
    "content",
    "image",
    "prompt_injection",
    "threat_intel",
)

CATEGORY_LABELS = {
    "header_auth": "邮件认证",
    "sender_identity": "发件人身份",
    "url": "链接",
    "attachment": "附件",
    "content": "正文语义",
    "image": "图片/二维码",
    "prompt_injection": "提示注入",
    "threat_intel": "威胁情报",
}

POLARITY_RISK = "risk"
POLARITY_MITIGATING = "mitigating"


@dataclass
class Evidence:
    """One atomic, human-auditable observation.

    ``severity`` answers "how bad would this be if true", ``confidence``
    answers "how sure are we that it is true".  The product of the two is the
    weight used by the scorer.  Evidence never comes from the LLM: it always
    has a deterministic detector or a named tool as its source.
    """

    id: str = ""
    category: str = "content"
    title: str = ""
    detail: str = ""
    severity: float = 0.0
    confidence: float = 0.8
    source: str = ""
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    polarity: str = POLARITY_RISK
    verifiable: bool = True

    def weight(self) -> float:
        return clamp(self.severity) * clamp(self.confidence)

    def has_tag(self, tag: str) -> bool:
        return tag in self.tags

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def make_evidence(
    category: str,
    title: str,
    detail: str,
    severity: float,
    confidence: float = 0.8,
    source: str = "",
    tags: list[str] | None = None,
    raw: dict[str, Any] | None = None,
    polarity: str = POLARITY_RISK,
    verifiable: bool = True,
) -> Evidence:
    """Convenience constructor used by detectors and tools."""
    return Evidence(
        category=category if category in CATEGORIES else "content",
        title=title,
        detail=detail,
        severity=clamp(severity),
        confidence=clamp(confidence),
        source=source,
        tags=list(tags or []),
        raw=dict(raw or {}),
        polarity=polarity,
        verifiable=verifiable,
    )


@dataclass
class ToolCall:
    id: str = ""
    tool: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    tool: str = ""
    ok: bool = True
    data: dict[str, Any] = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    error: str = ""
    latency_ms: float = 0.0
    params: dict[str, Any] = field(default_factory=dict)
    cached: bool = False

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


@dataclass
class AnalysisStep:
    phase: str = ""
    title: str = ""
    detail: str = ""
    elapsed_ms: float = 0.0
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScoreBreakdown:
    raw_score: float = 0.0
    pre_llm_score: float = 0.0
    final_score: float = 0.0
    category_scores: dict[str, float] = field(default_factory=dict)
    category_contributions: dict[str, float] = field(default_factory=dict)
    mitigation_points: float = 0.0
    floor: float | None = None
    floor_reasons: list[str] = field(default_factory=list)
    llm_adjustment: float = 0.0
    confidence: float = 0.5
    risk_level: str = "Low"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalystOutput:
    summary: str = ""
    reasoning_steps: list[str] = field(default_factory=list)
    cited_evidence_ids: list[str] = field(default_factory=list)
    suggested_score: float | None = None
    confidence: float = 0.5
    conflicts: list[str] = field(default_factory=list)
    injection_suspected: bool = False
    provider: str = "heuristic"
    model: str = ""
    raw_text: str = ""
    valid: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisReport:
    email_id: str = ""
    subject: str = ""
    sender: str = ""
    risk_score: float = 0.0
    risk_level: str = "Low"
    action: str = "Allow"
    confidence: float = 0.5
    summary: str = ""
    evidence_chain: list[Evidence] = field(default_factory=list)
    reasoning_steps: list[str] = field(default_factory=list)
    score_breakdown: ScoreBreakdown = field(default_factory=ScoreBreakdown)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    analysis_steps: list[AnalysisStep] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    injection_detected: bool = False
    recommended_actions: list[str] = field(default_factory=list)
    engine: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    email_snapshot: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def top_evidence(self) -> list[Evidence]:
        risks = [e for e in self.evidence_chain if e.polarity == POLARITY_RISK]
        return sorted(risks, key=lambda e: e.weight(), reverse=True)
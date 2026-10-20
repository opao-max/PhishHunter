"""Attachment static analysis.

Only filename, extension and declared MIME type are inspected.  Hashes are
forwarded to the threat-intelligence tool layer and are never treated as
evidence by themselves.
"""

from __future__ import annotations

import re

from ..models import Attachment, EmailMessage, Evidence, make_evidence

SOURCE = "attachment_analysis"

# Extension -> acceptable MIME types.  A missing entry means "unknown, do not
# judge".  MIME types are compared after stripping parameters/case.
_MIME_EXPECTATIONS: dict[str, frozenset[str]] = {
    ".pdf": frozenset({"application/pdf", "application/x-pdf"}),
    ".doc": frozenset({"application/msword"}),
    ".docx": frozenset(
        {"application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    ),
    ".docm": frozenset({"application/vnd.ms-word.document.macroenabled.12"}),
    ".xls": frozenset({"application/vnd.ms-excel"}),
    ".xlsx": frozenset(
        {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
    ),
    ".xlsm": frozenset({"application/vnd.ms-excel.sheet.macroenabled.12"}),
    ".ppt": frozenset({"application/vnd.ms-powerpoint"}),
    ".pptx": frozenset(
        {"application/vnd.openxmlformats-officedocument.presentationml.presentation"}
    ),
    ".pptm": frozenset({"application/vnd.ms-powerpoint.presentation.macroenabled.12"}),
    ".zip": frozenset({"application/zip", "application/x-zip-compressed"}),
    ".rar": frozenset({"application/vnd.rar", "application/x-rar-compressed"}),
    ".7z": frozenset({"application/x-7z-compressed"}),
    ".gz": frozenset({"application/gzip", "application/x-gzip"}),
    ".tar": frozenset({"application/x-tar"}),
    ".exe": frozenset(
        {
            "application/x-msdownload",
            "application/x-dosexec",
            "application/vnd.microsoft.portable-executable",
            "application/x-msdos-program",
        }
    ),
    ".js": frozenset({"application/javascript", "text/javascript", "application/x-javascript"}),
    ".vbs": frozenset({"application/x-vbs", "text/vbscript"}),
    ".bat": frozenset({"application/bat", "application/x-bat", "text/plain"}),
    ".cmd": frozenset({"application/cmd", "application/x-cmd", "text/plain"}),
    ".ps1": frozenset({"application/x-powershell", "text/plain"}),
    ".lnk": frozenset({"application/x-ms-shortcut"}),
    ".iso": frozenset({"application/x-iso9660-image", "application/octet-stream"}),
    ".png": frozenset({"image/png"}),
    ".jpg": frozenset({"image/jpeg"}),
    ".jpeg": frozenset({"image/jpeg"}),
    ".gif": frozenset({"image/gif"}),
    ".webp": frozenset({"image/webp"}),
    ".svg": frozenset({"image/svg+xml"}),
    ".txt": frozenset({"text/plain"}),
    ".html": frozenset({"text/html", "application/xhtml+xml"}),
}

_GENERIC_MIMES = frozenset(
    {
        "",
        "application/octet-stream",
        "binary/octet-stream",
        "application/download",
        "application/force-download",
        "application/unknown",
    }
)

_LURE_RE = re.compile(
    r"(invoice|payment|receipt|resume|cv|urgent|scan|photo|document|statement|"
    r"发票|付款|回款|简历|紧急|扫描|照片|对账单)",
    re.IGNORECASE,
)

_ARCHIVE_PASSWORD_RE = re.compile(
    r"(解压密码|压缩密码|压缩包密码|压缩文件密码|"
    r"password\s*(?:for|to)\s*(?:the\s*)?(?:archive|zip|file)|"
    r"archive\s*password|protected\s*archive|encrypted\s*(?:archive|zip))",
    re.IGNORECASE,
)


_TITLE_PRIORITY = (
    "double_extension",
    "executable_attachment",
    "macro_document",
    "mime_mismatch",
    "archive_attachment",
)
_TITLE_BY_CODE = {
    "double_extension": "附件使用双扩展名伪装",
    "executable_attachment": "邮件包含可执行附件",
    "macro_document": "附件为启用宏的 Office 文档",
    "mime_mismatch": "附件 MIME 类型与扩展名不一致",
    "archive_attachment": "邮件包含压缩包附件",
}


def _normalize_mime(value: str) -> str:
    return (value or "").split(";", 1)[0].strip().lower()


def _mime_mismatch(attachment: Attachment) -> tuple[str, str] | None:
    """Return ``(declared_mime, expected_example)`` when the pair is wrong."""
    declared = _normalize_mime(attachment.mime_type)
    extension = attachment.extension
    if not declared or declared in _GENERIC_MIMES or not extension:
        return None
    expected = _MIME_EXPECTATIONS.get(extension)
    if not expected:
        return None
    if declared in expected:
        return None
    # Images may legitimately use any image/* subtype when the extension is
    # generic (e.g. ``.jpg`` served as ``image/pjpeg``).
    if declared.startswith("image/") and next(iter(expected)).startswith("image/"):
        return None
    return declared, sorted(expected)[0]


def _collect_findings(
    attachment: Attachment, email: EmailMessage
) -> list[tuple[str, str, float, tuple[str, ...]]]:
    """Return ``(code, detail, severity, tags)`` tuples for one attachment."""
    findings: list[tuple[str, str, float, tuple[str, ...]]] = []
    filename = attachment.filename or "(未命名附件)"
    extensions = attachment.extensions

    if attachment.has_double_extension:
        findings.append(
            (
                "double_extension",
                f"文件名 {filename} 以 {extensions[-2]} 结尾，但实际扩展名是可执行的 "
                f"{extensions[-1]}，用于诱导用户双击运行。",
                0.95,
                ("double_extension",),
            )
        )

    if attachment.is_executable:
        findings.append(
            (
                "executable_attachment",
                f"附件扩展名 {attachment.extension} 属于可直接执行的文件类型（{filename}）。",
                0.8,
                ("executable_attachment",),
            )
        )

    if attachment.is_macro_document:
        findings.append(
            (
                "macro_document",
                f"附件 {filename} 是启用宏的 Office 文档，打开后可能执行 VBA 载荷。",
                0.72,
                ("macro_document",),
            )
        )

    if attachment.is_archive:
        password_hint = bool(_ARCHIVE_PASSWORD_RE.search(email.body_text or ""))
        password_hint = password_hint or bool(_ARCHIVE_PASSWORD_RE.search(filename))
        if password_hint:
            findings.append(
                (
                    "archive_attachment",
                    f"附件 {filename} 是压缩包，且正文/文件名提供了密码提示，"
                    "攻击者常用加密压缩包绕过扫描引擎。",
                    0.62,
                    ("archive_attachment", "encrypted_archive"),
                )
            )
        else:
            findings.append(
                (
                    "archive_attachment",
                    f"附件 {filename} 是压缩包，内容无法被邮件网关直接检查。",
                    0.45,
                    ("archive_attachment",),
                )
            )

    mismatch = _mime_mismatch(attachment)
    if mismatch is not None:
        declared, expected = mismatch
        tags = ["mime_mismatch"]
        if declared.startswith("image/"):
            tags.append("image_masquerade")
        findings.append(
            (
                "mime_mismatch",
                f"附件 {filename} 声明 MIME 为 {declared}，但扩展名 {attachment.extension} "
                f"应对应 {expected}，存在类型伪装。",
                0.76 if "image_masquerade" in tags else 0.74,
                tuple(tags),
            )
        )

    if _LURE_RE.search(filename) and (
        attachment.is_executable
        or attachment.is_macro_document
        or attachment.has_double_extension
    ):
        findings.append(
            (
                "lure_filename",
                f"附件名 {filename} 使用业务诱饵词（发票/付款/简历等），并与危险文件类型组合。",
                0.55,
                ("lure_filename",),
            )
        )

    return findings


def _build_evidence(
    attachment: Attachment, findings: list[tuple[str, str, float, tuple[str, ...]]]
) -> Evidence:
    codes = [item[0] for item in findings]
    primary = next((code for code in _TITLE_PRIORITY if code in codes), codes[0])
    title = _TITLE_BY_CODE.get(primary, "附件存在可疑特征")
    detail = f"附件「{attachment.filename or '未命名'}」：" + "；".join(
        f"{index}) {item[1]}" for index, item in enumerate(findings, start=1)
    )
    severity = min(
        0.97, max(item[2] for item in findings) + 0.02 * (len(findings) - 1)
    )
    tags: list[str] = []
    for item in findings:
        for tag in item[3]:
            if tag not in tags:
                tags.append(tag)
    return make_evidence(
        "attachment",
        title,
        detail,
        severity,
        confidence=0.92,
        source=SOURCE,
        tags=tags,
        raw={
            "filename": attachment.filename,
            "extension": attachment.extension,
            "extensions": attachment.extensions,
            "mime_type": attachment.mime_type,
            "hash": attachment.hash,
            "signals": codes,
        },
    )


def analyze_attachments(email: EmailMessage) -> list[Evidence]:
    """Return one aggregated evidence item per suspicious attachment."""
    if not email.attachments:
        return []

    evidence: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    for attachment in email.attachments:
        key = (attachment.filename.strip().lower(), attachment.hash.strip().lower())
        if key in seen:
            continue
        seen.add(key)
        findings = _collect_findings(attachment, email)
        if findings:
            evidence.append(_build_evidence(attachment, findings))
    return evidence
"""Prompt-injection guard for untrusted email content.

Emails are data, never instructions.  This module detects common attempts to
steer the downstream LLM analyst (instruction override, role manipulation,
verdict steering, fabricated tool output) and hidden/obfuscated content, and it
provides a structural neutralizer used before any email text reaches a model.

Detection is intentionally conservative: a security-awareness email that merely
discusses these phrases may still be flagged, but the resulting evidence is
low-weight relative to the deterministic URL/attachment signals.
"""

from __future__ import annotations

import base64
import re

from ..models import EmailMessage, Evidence, make_evidence

SOURCE = "injection_guard"

_GROUP_LABELS = {
    "instruction_override": "指令覆盖",
    "role_manipulation": "角色/系统提示操纵",
    "verdict_steering": "结论操纵",
    "fake_tool_result": "伪造工具结果",
}

_GROUP_SEVERITY = {
    "instruction_override": 0.9,
    "role_manipulation": 0.84,
    "verdict_steering": 0.86,
    "fake_tool_result": 0.8,
}

# Each entry: (group, human label, compiled pattern).
_TEXT_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # -- instruction override: English ------------------------------------ #
    (
        "instruction_override",
        "忽略先前指令",
        re.compile(
            r"\bignore\s+(?:all\s+)?(?:of\s+)?(?:the\s+|your\s+)?"
            r"(?:previous|prior|above|earlier|foregoing)\s+"
            r"(?:instructions?|prompts?|rules?|directions?|guidelines?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        "无视先前指令",
        re.compile(
            r"\bdisregard\s+(?:all\s+)?(?:of\s+)?(?:the\s+|your\s+)?"
            r"(?:previous|prior|above|earlier|system)\s+"
            r"(?:instructions?|prompts?|rules?|directions?|guidelines?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        "忘记规则",
        re.compile(
            r"\bforget\s+(?:all\s+)?(?:your\s+|the\s+|these\s+)?"
            r"(?:rules|instructions|prompts|guidelines|restrictions)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "instruction_override",
        "绕过安全策略",
        re.compile(
            r"\b(?:bypass|override|disable|ignore)\s+(?:all\s+)?(?:the\s+)?"
            r"(?:safety|security|content)\s+(?:rules|filters|policies|guidelines|guardrails)\b",
            re.IGNORECASE,
        ),
    ),
    # -- instruction override: Chinese ------------------------------------ #
    (
        "instruction_override",
        "忽略先前指令（中文）",
        # Bounded whitespace and at most one prefix token per group; stacked
        # unbounded \s* optionals can backtrack exponentially on long runs.
        re.compile(
            r"忽略(?:掉)?[ \t]{0,8}"
            r"(?:(?:之前|以上|前面|此前|上面|你的?)[ \t]{0,8})?"
            r"(?:的[ \t]{0,4})?"
            r"(?:所有[ \t]{0,8})?"
            r"(?:的[ \t]{0,4})?"
            r"(?:指令|指示|规则|提示|要求|限制)"
        ),
    ),
    (
        "instruction_override",
        "无视规则（中文）",
        re.compile(
            r"无视[ \t]{0,8}"
            r"(?:(?:之前|以上|前面|此前|上面)[ \t]{0,8})?"
            r"(?:的[ \t]{0,4})?"
            r"(?:所有[ \t]{0,8})?"
            r"(?:的[ \t]{0,4})?"
            r"(?:指令|指示|规则|提示|要求|限制|系统)"
        ),
    ),
    (
        "instruction_override",
        "忘记规则（中文）",
        re.compile(
            r"忘记[ \t]{0,8}"
            r"(?:(?:你的?|之前的?|所有的?)[ \t]{0,8})?"
            r"(?:规则|指令|提示|设定|限制)"
        ),
    ),
    (
        "instruction_override",
        "作废安全规则（中文）",
        re.compile(
            r"(?:把|将)[^。！？\n]{0,20}(?:安全)?(?:规则|指令|限制)"
            r"[^。！？\n]{0,12}(?:作废|取消|废除|忽略|忘记)"
        ),
    ),
    # -- role / system manipulation --------------------------------------- #
    (
        "role_manipulation",
        "角色重设",
        re.compile(
            r"\byou\s+are\s+now\s+(?:a|an|the|my|DAN|developer|system|admin(?:istrator)?|"
            r"unrestricted|root|sudo)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_manipulation",
        "伪装系统角色",
        re.compile(
            r"\bact\s+as\s+(?:a|an|the)?\s*(?:system|developer|admin(?:istrator)?|assistant|"
            r"security\s+analyst|unrestricted|DAN|root|sudo)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "role_manipulation",
        "系统提示词",
        re.compile(r"\bsystem\s+(?:prompt|message|instruction)\b", re.IGNORECASE),
    ),
    (
        "role_manipulation",
        "开发者消息",
        re.compile(r"\bdeveloper\s+(?:message|mode|prompt|instruction)\b", re.IGNORECASE),
    ),
    (
        "role_manipulation",
        "越狱",
        re.compile(r"\bjailbreak(?:ed|ing|s)?\b|\bDAN\s+mode\b|\bdo\s+anything\s+now\b", re.IGNORECASE),
    ),
    (
        "role_manipulation",
        "DAN 越狱人格",
        # Case-sensitive: avoids flagging ordinary names such as "Dan".
        re.compile(r"\bDAN\b"),
    ),
    (
        "role_manipulation",
        "角色重设（中文）",
        re.compile(r"你现在是\s*(?:一个|一名|系统|管理员|审核员|开发者|DAN|安全|助手)"),
    ),
    (
        "role_manipulation",
        "系统提示词（中文）",
        re.compile(r"系统提示词|系统提示\b|开发者消息|越狱模式"),
    ),
    (
        "role_manipulation",
        "角色扮演（中文）",
        re.compile(r"扮演\s*(?:一个|一名)?\s*(?:系统|管理员|审核员|安全|开发者|无限制)"),
    ),
    (
        "role_manipulation",
        "要求扮演角色",
        re.compile(
            r"\bpretend\s+(?:that\s+)?(?:you\s+are|to\s+be)\s+(?:a|an|the)?\s*"
            r"(?:system|developer|admin(?:istrator)?|assistant|compliance|auditor|"
            r"security\s+analyst|unrestricted|root|sudo)\b",
            re.IGNORECASE,
        ),
    ),
    # -- verdict steering -------------------------------------------------- #
    (
        "verdict_steering",
        "要求视为合法",
        re.compile(
            r"\btreat\s+(?:this|it|the\s+(?:email|message|mail))\s+as\s+"
            r"(?:legitimate|safe|benign|clean|trusted|ham)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_steering",
        "要求不采取行动",
        re.compile(r"\btake\s+no\s+(?:action|further\s+action)\b", re.IGNORECASE),
    ),
    (
        "verdict_steering",
        "声称邮件合法",
        re.compile(
            r"\b(?:this|the)\s+(?:email|message|mail)\s+is\s+"
            r"(?:legitimate|safe|benign|clean|trusted|not\s+phishing)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_steering",
        "声称无需操作",
        re.compile(
            r"\bno\s+(?:further\s+)?action\s+is\s+(?:required|needed)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_steering",
        "要求安全忽略",
        re.compile(
            r"\b(?:you\s+)?(?:can|should|may)\s+safely\s+ignore\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_steering",
        "声称邮件安全（中文）",
        re.compile(r"(?:此|该|这封)\s*邮件\s*(?:是|为)?\s*(?:安全|合法|正常)的?"),
    ),
    (
        "verdict_steering",
        "声称无需操作（中文）",
        re.compile(r"无需\s*(?:采取)?\s*(?:任何)?\s*(?:操作|行动|处理)"),
    ),
    # -- verdict steering -------------------------------------------------- #
    (
        "verdict_steering",
        "要求分类为安全",
        re.compile(
            r"\bclassify\s+(?:this|it|the\s+(?:email|message|mail))\s+as\s+"
            r"(?:safe|legitimate|benign|clean|not\s+phishing|ham)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_steering",
        "要求输出 Allow",
        re.compile(
            r"\b(?:output|return|respond\s+with|answer)\s+[\"']?"
            r"(?:allow|benign|safe|legitimate|clean)[\"']?\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_steering",
        "要求不要标记",
        re.compile(
            r"\bdo\s+not\s+(?:flag|mark|report|block|quarantine)\b"
            r"(?:\s+(?:this|it|the\s+(?:email|message|mail)))?",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_steering",
        "要求标记为安全",
        re.compile(
            r"\bmark\s+(?:(?:this|it|the\s+(?:email|message|mail))\s+)?as\s+"
            r"(?:safe|benign|legitimate|clean|allow)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "verdict_steering",
        "操纵风险分",
        re.compile(r"\bset\s+(?:the\s+)?(?:risk\s+)?score\s+(?:to\s+)?(?:0|zero)\b", re.IGNORECASE),
    ),
    (
        "verdict_steering",
        "判定为安全（中文）",
        re.compile(r"判定为\s*(?:安全|正常|合法|放行|白名单)|评为\s*(?:安全|正常|合法)"),
    ),
    (
        "verdict_steering",
        "输出 Allow（中文）",
        re.compile(r"(?:输出|返回|回答)\s*[\"']?(?:allow|safe|正常|放行)", re.IGNORECASE),
    ),
    (
        "verdict_steering",
        "不要报警（中文）",
        re.compile(r"不要\s*(?:报警|报告|拦截|标记|隔离)"),
    ),
    (
        "verdict_steering",
        "标记为安全（中文）",
        re.compile(r"标记为\s*(?:安全|正常|合法|白名单)"),
    ),
    (
        "verdict_steering",
        "操纵风险分（中文）",
        re.compile(r"风险(?:评分|分数|值)?\s*(?:设为|设置为|改为)\s*(?:0|零)"),
    ),
    # -- fabricated tool output ------------------------------------------- #
    (
        "fake_tool_result",
        "伪造 WHOIS 结果",
        re.compile(
            r"\bwhois\b[^.\n]{0,80}\b(?:shows|says|indicates|reports|confirms|states)\b"
            r"[^.\n]{0,80}\b(?:registered|created|established)\b"
            r"[^.\n]{0,60}\b(?:years?|months?|days?)\s+ago\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_tool_result",
        "伪造 VirusTotal 结果",
        re.compile(
            r"\b(?:virustotal|virus\s+total|vt)\b[^.\n]{0,40}"
            r"\b(?:says|shows|reports|indicates|confirms|detects?)\b"
            r"[^.\n]{0,40}\b(?:clean|safe|no\s+(?:detections?|threats?|malware))\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_tool_result",
        "伪造沙箱结果",
        re.compile(
            r"\b(?:sandbox|sand\s*box)\b[^.\n]{0,50}"
            r"\b(?:found|shows|reports|returned|indicates)\b"
            r"[^.\n]{0,50}\b(?:no\s+(?:malware|threats?|suspicious|issues?|problems?)|clean|safe)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_tool_result",
        "伪造 VirusTotal 零检出",
        re.compile(
            r"\b(?:virustotal|virus\s+total|vt)\b[^.\n]{0,60}"
            r"\b(?:finds?|found|reports?|reported|shows?)\b[^.\n]{0,30}"
            r"\b(?:0|zero|no)\s+(?:detections?|hits?|threats?|malware)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_tool_result",
        "伪造域名注册年份",
        re.compile(
            r"\b(?:sender\s+domain|this\s+domain|the\s+domain|domain)\b"
            r"[^.\n]{0,50}\b(?:was\s+)?(?:registered|established|created)\s+"
            r"(?:in\s+)?(?:19|20)\d{2}\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_tool_result",
        "伪造沙箱零发现",
        re.compile(
            r"\b(?:sandbox|sand\s*box)\b[^.\n]{0,70}"
            r"\b(?:produced|found|returned|reported)\b[^.\n]{0,30}"
            r"\b(?:zero|no)\s+(?:findings|detections|threats|malware|issues)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_tool_result",
        "伪造威胁情报结论",
        re.compile(
            r"\b(?:threat\s+intel(?:ligence)?|intel)\b[^.\n]{0,40}"
            r"\b(?:shows|says|indicates|confirms|reports)\b"
            r"[^.\n]{0,40}\b(?:clean|safe|benign|trusted)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "fake_tool_result",
        "伪造情报结论（中文）",
        re.compile(r"情报(?:显示|表明|确认|指出)[^。！？\n]{0,30}(?:安全|可信|无风险|干净|清白)"),
    ),
    (
        "fake_tool_result",
        "伪造域名年龄（中文）",
        re.compile(r"(?:域名|网站|证书)(?:注册于|建立于|创建于|已经注册)[^。！？\n]{0,20}(?:年前|多年|十年|数年)"),
    ),
    (
        "fake_tool_result",
        "伪造检测结论（中文）",
        re.compile(
            r"(?:病毒|沙箱|信誉)(?:检测|扫描|分析)?(?:结果)?[^。！？\n]{0,20}"
            r"(?:为)?(?:安全|干净|无威胁|无恶意)"
        ),
    ),
)

_HIDDEN_STYLE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"display\s*:\s*none", re.IGNORECASE), "display:none"),
    (re.compile(r"visibility\s*:\s*hidden", re.IGNORECASE), "visibility:hidden"),
    (
        re.compile(r"font-size\s*:\s*0(?:\.0+)?\s*(?:px|pt|em|rem|%)?(?![\w.])", re.IGNORECASE),
        "font-size:0",
    ),
    (re.compile(r"opacity\s*:\s*0(?:\.0+)?(?![\d.])", re.IGNORECASE), "opacity:0"),
    # Off-screen positioning is a classic way to hide text from humans while
    # keeping it in the HTML that an automated reader may process.
    (re.compile(r"(?:left|top|text-indent)\s*:\s*-\d{3,}(?:px|em|rem)", re.IGNORECASE), "offscreen"),
    (re.compile(r"clip-path\s*:\s*inset\(\s*(?:4[5-9]|50)\s*%", re.IGNORECASE), "clip-path"),
    (re.compile(r"transform\s*:\s*scale\(\s*0(?:\.0+)?\s*\)", re.IGNORECASE), "scale(0)"),
    (re.compile(r"max-height\s*:\s*0(?:px)?(?![\w.])", re.IGNORECASE), "max-height:0"),
)

_STYLE_ATTR_RE = re.compile(r"""style\s*=\s*(?:"([^"]*)"|'([^']*)')""", re.IGNORECASE)
_STYLE_BLOCK_RE = re.compile(r"<style\b[^>]*>(.*?)</style\s*>", re.IGNORECASE | re.DOTALL)
_HIDDEN_ATTR_RE = re.compile(
    r"<[^>]*\s(?:hidden\b|aria-hidden\s*=\s*[\"']true[\"'])[^>]*>", re.IGNORECASE
)
_WHITE_VALUES = frozenset(
    {"white", "#fff", "#ffffff", "rgb(255,255,255)", "rgba(255,255,255,1)"}
)
_ZERO_WIDTH_RE = re.compile(
    "[\u00ad\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060-\u2064\ufeff]"
)
_WHITESPACE_RUN_RE = re.compile(r"[ \t\r\n\u3000]+")
_BASE64_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{180,}={0,2})(?![A-Za-z0-9+/=_-])"
)
# Short base64 callouts are common in benign emails, so we only decode them to
# inspect the payload; a hit requires instruction-level text after decoding.
_B64_CANDIDATE_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/=_-])"
)


def _decode_base64_blobs(text: str, limit: int = 8) -> list[str]:
    """Decode printable base64-looking blobs for inspection (never executed)."""
    decoded: list[str] = []
    for match in _B64_CANDIDATE_RE.finditer(text or ""):
        token = match.group(1).replace("-", "+").replace("_", "/")
        token += "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(token, validate=True)
        except (ValueError, TypeError):
            continue
        try:
            value = raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                value = raw.decode("latin-1")
            except UnicodeDecodeError:
                continue
        if not value:
            continue
        printable = sum(ch.isprintable() or ch in "\r\n\t" for ch in value)
        if printable / len(value) >= 0.85:
            decoded.append(value)
        if len(decoded) >= limit:
            break
    return decoded

_DELIMITER_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"<\s*/?\s*untrusted_email_content\s*>", re.IGNORECASE),
        "<untrusted_email_content>",
    ),
    (re.compile(r"<\s*/?\s*system\s*>", re.IGNORECASE), "<system>"),
    (
        re.compile(r"<\|\s*(?:im_start|im_end|system|user|assistant)\s*\|>", re.IGNORECASE),
        "<|chat token|>",
    ),
    (
        re.compile(r"<\s*/?\s*(?:assistant|developer)\s*>", re.IGNORECASE),
        "<assistant>/<developer>",
    ),
)


def _snippet(value: str, limit: int = 120) -> str:
    value = re.sub(r"\s+", " ", value or "").strip()
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _text_matches(text: str) -> list[tuple[str, str, str]]:
    """Return ``(group, label, matched_text)`` for every text rule hit."""
    # Collapse whitespace runs before matching so arbitrary padding cannot
    # evade the bounded quantifiers (and keeps matching linear-time).
    text = _WHITESPACE_RUN_RE.sub(" ", text or "")
    matches: list[tuple[str, str, str]] = []
    for group, label, pattern in _TEXT_RULES:
        for match in pattern.finditer(text or ""):
            matches.append((group, label, _snippet(match.group(0))))
    return matches


def _is_white(value: str) -> bool:
    normalized = re.sub(r"\s+", "", (value or "").lower())
    return normalized in _WHITE_VALUES


def _hidden_declaration_labels(style: str) -> list[str]:
    labels: list[str] = []
    for pattern, label in _HIDDEN_STYLE_RULES:
        if pattern.search(style or ""):
            labels.append(label)
    declarations: dict[str, str] = {}
    for part in (style or "").split(";"):
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        declarations[key.strip().lower()] = value.strip()
    width = declarations.get("width", "")
    height = declarations.get("height", "")
    overflow = declarations.get("overflow", "")
    if (
        overflow.strip().lower() == "hidden"
        and re.fullmatch(r"\s*[012](?:\.\d+)?(?:px)?\s*", width)
        and re.fullmatch(r"\s*[012](?:\.\d+)?(?:px)?\s*", height)
    ):
        labels.append("1px-hidden")
    return list(dict.fromkeys(labels))


def _hidden_html_matches(html_text: str) -> list[tuple[str, str]]:
    """Return ``(label, snippet)`` for hidden HTML techniques."""
    html_text = html_text or ""
    if not html_text:
        return []
    matches: list[tuple[str, str]] = []
    for match in _STYLE_ATTR_RE.finditer(html_text):
        style = match.group(1) if match.group(1) is not None else match.group(2) or ""
        for label in _hidden_declaration_labels(style):
            matches.append((label, _snippet(match.group(0))))
        declarations: dict[str, str] = {}
        for part in style.split(";"):
            if ":" not in part:
                continue
            key, value = part.split(":", 1)
            declarations[key.strip().lower()] = value.strip()
        color = declarations.get("color", "")
        background = declarations.get("background-color") or declarations.get("background", "")
        if _is_white(color) and _is_white(background):
            matches.append(("white-on-white", _snippet(match.group(0))))

    # Class/id-based hiding declared in a <style> block is the normal pattern
    # in HTML email; only report a rule when the class/id is actually used.
    for style_match in _STYLE_BLOCK_RE.finditer(html_text):
        css = style_match.group(1) or ""
        for rule in re.finditer(r"([^{}]+)\{([^{}]*)\}", css):
            selectors, body = rule.group(1), rule.group(2)
            labels = _hidden_declaration_labels(body)
            if not labels:
                continue
            classes = re.findall(r"\.([A-Za-z0-9_-]+)", selectors)
            ids = re.findall(r"#([A-Za-z0-9_-]+)", selectors)
            used = any(
                re.search(
                    rf"""class\s*=\s*["'][^"']*\b{re.escape(name)}\b""",
                    html_text,
                    re.IGNORECASE,
                )
                for name in classes
            )
            used = used or any(
                re.search(
                    rf"""id\s*=\s*["']{re.escape(name)}["']""",
                    html_text,
                    re.IGNORECASE,
                )
                for name in ids
            )
            if used or not (classes or ids):
                matches.append(("CSS 隐藏样式", _snippet(rule.group(0))))

    for match in _HIDDEN_ATTR_RE.finditer(html_text):
        matches.append(("hidden 属性", _snippet(match.group(0))))
    return matches


def _hidden_findings(text: str, body_html: str) -> list[tuple[str, str]]:
    """Return hidden/obfuscation findings as ``(label, detail)`` pairs."""
    findings: list[tuple[str, str]] = []
    html_hits = _hidden_html_matches(body_html)
    if html_hits:
        labels = list(dict.fromkeys(label for label, _ in html_hits))
        example = html_hits[0][1]
        findings.append(
            (
                "隐藏 HTML",
                f"发现 {len(html_hits)} 处隐藏样式（{', '.join(labels)}），示例：{example}",
            )
        )

    zero_width = _ZERO_WIDTH_RE.findall(text)
    if zero_width:
        findings.append(
            ("零宽字符", f"正文含 {len(zero_width)} 个零宽/双向控制字符，可能用于隐藏关键词")
        )

    base64_hits = _BASE64_RE.findall(text)
    if base64_hits:
        longest = max(len(item) for item in base64_hits)
        findings.append(
            ("长 Base64 块", f"发现 {len(base64_hits)} 段超长 Base64 编码（最长 {longest} 字符）")
        )
    return findings


def _contains_hidden(text: str, body_html: str) -> bool:
    if _ZERO_WIDTH_RE.search(text or ""):
        return True
    if _BASE64_RE.search(text or ""):
        return True
    return bool(_hidden_html_matches(body_html))


def contains_injection(text: str) -> bool:
    """Whether *text* contains instruction-level injection or hidden content."""
    text = text or ""
    if _text_matches(text):
        return True
    for blob in _decode_base64_blobs(text):
        if _text_matches(blob):
            return True
    return _contains_hidden(text, text)


def neutralize(text: str, max_chars: int = 6000) -> tuple[str, list[str]]:
    """Remove injection framing from untrusted text.

    Zero-width/bidi controls are stripped, delimiter-breaking tags are replaced
    with a neutral marker, and the result is truncated.  The returned findings
    are human-readable Chinese notes suitable for an audit log.
    """
    cleaned = text or ""
    findings: list[str] = []

    zero_width_count = len(_ZERO_WIDTH_RE.findall(cleaned))
    if zero_width_count:
        cleaned = _ZERO_WIDTH_RE.sub("", cleaned)
        findings.append(f"已移除 {zero_width_count} 个零宽/双向控制字符")

    for pattern, label in _DELIMITER_RULES:
        cleaned, count = pattern.subn("[NEUTRALIZED_DELIMITER]", cleaned)
        if count:
            findings.append(f"已中和分隔符 {label} × {count}")

    if max_chars and len(cleaned) > max_chars:
        findings.append(f"内容超长，已截断至 {max_chars} 字符")
        cleaned = cleaned[:max_chars]
    return cleaned, findings


def scan_injection(email: EmailMessage) -> list[Evidence]:
    """Return up to two aggregated prompt-injection evidence items."""
    text_fields = [email.subject, email.body_text, email.body_html]
    combined = "\n".join(value for value in text_fields if value)
    if not combined.strip():
        return []

    evidence: list[Evidence] = []

    text_hits = _text_matches(combined)
    decoded_hits: list[tuple[str, str, str]] = []
    for blob in _decode_base64_blobs(combined):
        for group, label, matched in _text_matches(blob):
            decoded_hits.append((group, label + "（Base64 解码后）", matched))
    text_hits.extend(decoded_hits)

    if text_hits:
        groups: list[str] = []
        for group, _, _ in text_hits:
            if group not in groups:
                groups.append(group)
        severity = min(
            0.95, max(_GROUP_SEVERITY[group] for group in groups) + 0.02 * (len(groups) - 1)
        )
        tags = list(groups)
        unique_hits: list[tuple[str, str, str]] = []
        seen_snippets: set[str] = set()
        for hit in text_hits:
            if hit[2] in seen_snippets:
                continue
            seen_snippets.add(hit[2])
            unique_hits.append(hit)
        detail = f"在主题/正文中发现 {len(unique_hits)} 处指令型内容：" + "；".join(
            f"{index}) {label}：{snippet}"
            for index, (_, label, snippet) in enumerate(unique_hits[:6], start=1)
        )
        evidence.append(
            make_evidence(
                "prompt_injection",
                "检测到提示注入/结论操纵指令",
                detail,
                severity,
                confidence=0.9,
                source=SOURCE,
                tags=tags,
                raw={
                    "groups": groups,
                    "matches": [
                        {"group": group, "label": label, "text": snippet}
                        for group, label, snippet in unique_hits[:12]
                    ],
                },
            )
        )

    hidden = _hidden_findings(combined, email.body_html)
    if hidden:
        hidden_severity = 0.72
        labels = {label for label, _ in hidden}
        if labels & {"隐藏 HTML", "CSS 隐藏样式", "hidden 属性"}:
            hidden_severity = 0.82
        if "隐藏 HTML" in labels:
            hidden_severity = 0.85
        evidence.append(
            make_evidence(
                "prompt_injection",
                "检测到隐藏或混淆内容",
                "；".join(detail for _, detail in hidden) + "。隐藏内容可能用于绕过人工审核或诱导模型。",
                hidden_severity,
                confidence=0.88,
                source=SOURCE,
                tags=["hidden_content"],
                raw={"findings": [{"label": label, "detail": detail} for label, detail in hidden]},
            )
        )

    return evidence
"""Human-facing renderers for :class:`~phishhunter.models.AnalysisReport`.

Three deterministic renderers share the same content model:

* ``render_text``     - dependency-free plain text (safe for logs and CI)
* ``render_markdown`` - a portable report for tickets and design docs
* ``render_rich``     - optional ANSI/colour output via ``rich``

Formatting helpers are deliberately dumb: they never re-order or reinterpret
evidence.  What the analyst sees is exactly what the scorer saw.
"""

from __future__ import annotations

import json
import textwrap
import unicodedata
from typing import Any

from .models import (
    CATEGORY_LABELS,
    POLARITY_MITIGATING,
    AnalysisReport,
    Evidence,
)

RULE_WIDTH = 84
LABEL_WIDTH = 16

_ACTION_LABELS = {
    "Block": "Block（阻断）",
    "Quarantine": "Quarantine（隔离）",
    "Allow": "Allow（放行）",
}


# --------------------------------------------------------------------------- #
# small formatting helpers
# --------------------------------------------------------------------------- #


def _display_width(text: str) -> int:
    """Terminal cell width; CJK glyphs occupy two cells."""
    width = 0
    for char in str(text):
        width += 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
    return width


def _pad(text: Any, width: int) -> str:
    text = str(text)
    return text + " " * max(0, width - _display_width(text))


def _kv(label: str, value: Any, width: int = LABEL_WIDTH) -> str:
    return f"{_pad(label, width)}: {value}"


def _rule(char: str = "=") -> str:
    return char * RULE_WIDTH


def _score_color(score: float) -> str:
    """Risk colours mandated by the interface contract."""
    if score >= 70:
        return "red"
    if score >= 40:
        return "yellow"
    return "green"


def _action_text(action: str) -> str:
    return _ACTION_LABELS.get(action, action or "Allow")


def _polarity_text(evidence: Evidence) -> str:
    return "缓解" if evidence.polarity == POLARITY_MITIGATING else "风险"


def _category_text(category: str) -> str:
    return CATEGORY_LABELS.get(category, category or "其他")


def _safe_str(value: Any, default: str = "无") -> str:
    text = "" if value is None else str(value).strip()
    return text or default


def _format_params(params: Any, limit: int = 320) -> str:
    if not params:
        return "{}"
    try:
        text = json.dumps(params, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        text = str(params)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


def _wrap_lines(text: str, *, width: int = RULE_WIDTH, indent: str = "        ") -> list[str]:
    """Wrap free text while keeping every line inside the report width."""
    text = str(text or "").strip()
    if not text:
        return []
    available = max(24, width - _display_width(indent))
    lines: list[str] = []
    for paragraph in text.splitlines():
        paragraph = paragraph.strip()
        if not paragraph:
            continue
        wrapped = textwrap.wrap(
            paragraph,
            width=available,
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        lines.extend(f"{indent}{line}" for line in wrapped)
    return lines


def _tool_field(call: dict[str, Any], key: str, default: Any = "") -> Any:
    value = call.get(key, default)
    return default if value is None else value


def _mitigation_text(value: float) -> str:
    return f"-{value:.1f}" if value else "0.0"


def _format_latency(value: Any) -> str:
    try:
        return f"{float(value):.2f} ms"
    except (TypeError, ValueError):
        return "n/a"


def _evidence_sort_key(evidence: Evidence) -> tuple[int, float]:
    # Risk first, strongest first.  Mitigating evidence is kept in the chain.
    return (1 if evidence.polarity == POLARITY_MITIGATING else 0, -evidence.weight())


def _ordered_evidence(report: AnalysisReport) -> list[Evidence]:
    return sorted(report.evidence_chain or [], key=_evidence_sort_key)


def _category_rows(report: AnalysisReport) -> list[tuple[str, float, float]]:
    breakdown = report.score_breakdown
    rows: list[tuple[str, float, float]] = []
    for category, contribution in (breakdown.category_contributions or {}).items():
        score = (breakdown.category_scores or {}).get(category, 0.0)
        if contribution or score:
            rows.append((category, float(contribution or 0.0), float(score or 0.0)))
    rows.sort(key=lambda row: row[1], reverse=True)
    return rows


# --------------------------------------------------------------------------- #
# plain text
# --------------------------------------------------------------------------- #


def render_text(report: AnalysisReport) -> str:
    """Render a complete, dependency-free plain-text report."""
    if not isinstance(report, AnalysisReport):
        raise TypeError("render_text expects an AnalysisReport")

    breakdown = report.score_breakdown
    lines: list[str] = [_rule(), "PhishHunter 钓鱼邮件分析报告", _rule()]

    lines.append(_kv("邮件 ID", _safe_str(report.email_id, "未知")))
    lines.append(_kv("主题", _safe_str(report.subject)))
    lines.append(_kv("发件人", _safe_str(report.sender)))
    lines.append(_kv("风险评分", f"{report.risk_score:.1f} / 100  [{report.risk_level}]"))
    lines.append(_kv("处置建议", _action_text(report.action)))
    lines.append(_kv("置信度", f"{report.confidence:.2f}"))
    lines.append(_kv("分析耗时", _format_latency(report.latency_ms)))
    lines.append(_kv("生成时间", _safe_str(report.generated_at)))

    engine = report.engine or {}
    if engine:
        engine_bits = [
            engine.get("mode", ""),
            f"provider={engine.get('llm_provider', 'none')}",
            f"model={engine.get('llm_model') or 'n/a'}",
            f"planner={engine.get('planner', 'heuristic')}",
        ]
        lines.append(_kv("引擎", " / ".join(str(bit) for bit in engine_bits if bit)))
    if report.injection_detected:
        lines.append(_kv("提示注入", "已检测到（邮件内容按不可信数据处理，未执行其中指令）"))

    lines.append(_rule("-"))
    lines.append("【摘要】")
    for wrapped in _wrap_lines(report.summary or "（无摘要）", indent="  "):
        lines.append(wrapped)

    evidence = _ordered_evidence(report)
    lines.append("")
    lines.append(f"【证据链】共 {len(evidence)} 条")
    if not evidence:
        lines.append("  未产生证据。")
    for item in evidence:
        lines.append(
            f"  [{_safe_str(item.id, 'E???')}] {_polarity_text(item)} | "
            f"{_category_text(item.category)} | "
            f"严重度 {item.severity:.2f} | 置信度 {item.confidence:.2f}"
        )
        lines.append(f"        标题：{_safe_str(item.title)}")
        detail_prefix = "        详情："
        detail_lines = textwrap.wrap(
            _safe_str(item.detail, "（无详情）"),
            width=max(24, RULE_WIDTH - _display_width(detail_prefix)),
            break_long_words=False,
            break_on_hyphens=False,
        ) or ["（无详情）"]
        lines.append(detail_prefix + detail_lines[0])
        for continuation in detail_lines[1:]:
            lines.append(" " * _display_width(detail_prefix) + continuation)
        if item.tags:
            lines.append(f"        标签：{', '.join(item.tags)}")
        if item.source:
            lines.append(f"        来源：{item.source}")

    lines.append("")
    lines.append(f"【推理过程】共 {len(report.reasoning_steps)} 步")
    if not report.reasoning_steps:
        lines.append("  未提供推理步骤。")
    for index, step in enumerate(report.reasoning_steps, start=1):
        prefix = f"  {index}. "
        wrapped = textwrap.wrap(
            str(step).strip(),
            width=max(24, RULE_WIDTH - _display_width(prefix)),
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        lines.append(prefix + wrapped[0])
        for continuation in wrapped[1:]:
            lines.append(" " * _display_width(prefix) + continuation)

    lines.append("")
    lines.append("【评分明细】")
    lines.append(f"  原始证据分    : {breakdown.raw_score:.1f}")
    lines.append(f"  缓解扣减      : {_mitigation_text(breakdown.mitigation_points)}")
    if breakdown.floor is not None:
        lines.append(f"  策略下限      : {breakdown.floor:.1f}")
        for reason in breakdown.floor_reasons or []:
            lines.append(f"    原因：{reason}")
    else:
        lines.append("  策略下限      : 无")
    lines.append(f"  下限前得分    : {breakdown.pre_llm_score:.1f}")
    lines.append(f"  模型调整      : {breakdown.llm_adjustment:+.1f}")
    lines.append(f"  最终得分      : {breakdown.final_score:.1f}  ({breakdown.risk_level})")
    category_rows = _category_rows(report)
    lines.append("  分类贡献      :")
    if not category_rows:
        lines.append("    无")
    for category, contribution, cat_risk in category_rows:
        lines.append(
            f"    {_pad(_category_text(category), 14)} {contribution:6.2f} 分"
            f"（类别风险系数 {cat_risk:.2f}）"
        )

    lines.append("")
    lines.append(f"【工具调用】共 {len(report.tool_calls)} 次")
    if not report.tool_calls:
        lines.append("  未调用外部工具。")
    for call in report.tool_calls:
        call_id = _safe_str(_tool_field(call, "id"), "C??")
        tool = _safe_str(_tool_field(call, "tool"), "unknown")
        status = "成功" if _tool_field(call, "ok", True) else "失败"
        latency = _format_latency(_tool_field(call, "latency_ms", 0.0))
        lines.append(f"  [{call_id}] {tool} | 状态：{status} | 耗时：{latency}")
        reason = _safe_str(_tool_field(call, "reason"), "（未记录原因）")
        lines.append(f"        原因：{reason}")
        lines.append(f"        参数：{_format_params(_tool_field(call, 'params', {}))}")
        evidence_ids = _tool_field(call, "evidence_ids", []) or []
        if evidence_ids:
            lines.append(f"        证据：{', '.join(str(eid) for eid in evidence_ids)}")
        error = _safe_str(_tool_field(call, "error"), "")
        if error:
            lines.append(f"        错误：{error}")

    if report.analysis_steps:
        lines.append("")
        lines.append("【分析流水线】")
        for step in report.analysis_steps:
            lines.append(
                f"  {_pad(step.phase or '-', 10)} {_pad(step.title or '-', 26)}"
                f" {_format_latency(step.elapsed_ms)}"
            )
            if step.detail:
                lines.append(f"            {step.detail}")

    lines.append("")
    lines.append("【冲突与分歧】")
    if report.conflicts:
        for conflict in report.conflicts:
            lines.append(f"  - {conflict}")
    else:
        lines.append("  无")

    lines.append("")
    lines.append("【处置建议】")
    if report.recommended_actions:
        for index, action in enumerate(report.recommended_actions, start=1):
            lines.append(f"  {index}. {action}")
    else:
        lines.append("  无额外建议。")

    lines.append("")
    lines.append("【备注】")
    if report.notes:
        for note in report.notes:
            lines.append(f"  - {note}")
    else:
        lines.append("  无")

    lines.append(_rule())
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# markdown
# --------------------------------------------------------------------------- #


def _md_escape(value: Any) -> str:
    text = "" if value is None else str(value)
    return (
        text.replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\r", " ")
        .replace("\n", "<br>")
    )


def render_markdown(report: AnalysisReport) -> str:
    """Render the report as portable Markdown."""
    if not isinstance(report, AnalysisReport):
        raise TypeError("render_markdown expects an AnalysisReport")

    breakdown = report.score_breakdown
    out: list[str] = []
    out.append("# PhishHunter 钓鱼邮件分析报告")
    out.append("")
    out.append("| 字段 | 值 |")
    out.append("| --- | --- |")
    out.append(f"| 邮件 ID | `{_md_escape(report.email_id)}` |")
    out.append(f"| 主题 | {_md_escape(report.subject)} |")
    out.append(f"| 发件人 | `{_md_escape(report.sender)}` |")
    out.append(
        f"| **风险评分** | **{report.risk_score:.1f} / 100（{_md_escape(report.risk_level)}）** |"
    )
    out.append(f"| **处置建议** | **{_md_escape(_action_text(report.action))}** |")
    out.append(f"| 置信度 | {report.confidence:.2f} |")
    out.append(f"| 分析耗时 | {_format_latency(report.latency_ms)} |")
    out.append(f"| 生成时间 | {_md_escape(report.generated_at)} |")
    engine = report.engine or {}
    if engine:
        out.append(
            "| 引擎 | "
            + _md_escape(
                f"{engine.get('mode', '')} / provider={engine.get('llm_provider', 'none')}"
                f" / model={engine.get('llm_model') or 'n/a'}"
                f" / planner={engine.get('planner', 'heuristic')}"
            )
            + " |"
        )
    if report.injection_detected:
        out.append("| 提示注入 | 已检测到（内容按不可信数据处理） |")
    out.append("")

    out.append("## 摘要")
    out.append("")
    out.append(report.summary or "（无摘要）")
    out.append("")

    evidence = _ordered_evidence(report)
    out.append(f"## 证据链（{len(evidence)} 条）")
    out.append("")
    if evidence:
        out.append("| ID | 极性 | 类别 | 严重度 | 置信度 | 标题 | 详情 |")
        out.append("| --- | --- | --- | --- | --- | --- | --- |")
        for item in evidence:
            out.append(
                f"| {_md_escape(item.id)} | {_polarity_text(item)} | "
                f"{_md_escape(_category_text(item.category))} | {item.severity:.2f} | "
                f"{item.confidence:.2f} | {_md_escape(item.title)} | "
                f"{_md_escape(item.detail)} |"
            )
        tags = [
            f"- `{item.id}` {_polarity_text(item)}：{', '.join(item.tags)}"
            for item in evidence
            if item.tags
        ]
        if tags:
            out.append("")
            out.append("**证据标签**")
            out.append("")
            out.extend(tags)
    else:
        out.append("未产生证据。")
    out.append("")

    out.append(f"## 推理过程（{len(report.reasoning_steps)} 步）")
    out.append("")
    if report.reasoning_steps:
        for index, step in enumerate(report.reasoning_steps, start=1):
            out.append(f"{index}. {step}")
    else:
        out.append("未提供推理步骤。")
    out.append("")

    out.append("## 评分明细")
    out.append("")
    out.append("| 项目 | 数值 |")
    out.append("| --- | --- |")
    out.append(f"| 原始证据分 | {breakdown.raw_score:.1f} |")
    out.append(f"| 缓解扣减 | {_mitigation_text(breakdown.mitigation_points)} |")
    floor_text = f"{breakdown.floor:.1f}" if breakdown.floor is not None else "无"
    out.append(f"| 策略下限 | {floor_text} |")
    if breakdown.floor_reasons:
        out.append(
            f"| 下限原因 | {_md_escape('；'.join(breakdown.floor_reasons))} |"
        )
    out.append(f"| 下限前得分 | {breakdown.pre_llm_score:.1f} |")
    out.append(f"| 模型调整 | {breakdown.llm_adjustment:+.1f} |")
    out.append(f"| **最终得分** | **{breakdown.final_score:.1f}（{breakdown.risk_level}）** |")
    out.append("")
    category_rows = _category_rows(report)
    if category_rows:
        out.append("**分类贡献**")
        out.append("")
        out.append("| 类别 | 贡献 | 类别风险系数 |")
        out.append("| --- | --- | --- |")
        for category, contribution, cat_risk in category_rows:
            out.append(
                f"| {_md_escape(_category_text(category))} | "
                f"{contribution:.2f} | {cat_risk:.2f} |"
            )
        out.append("")

    out.append(f"## 工具调用（{len(report.tool_calls)} 次）")
    out.append("")
    if report.tool_calls:
        out.append("| ID | 工具 | 状态 | 耗时 | 原因 | 错误 |")
        out.append("| --- | --- | --- | --- | --- | --- |")
        for call in report.tool_calls:
            status = "成功" if _tool_field(call, "ok", True) else "失败"
            error = _md_escape(_tool_field(call, "error", "")) or "-"
            out.append(
                f"| {_md_escape(_tool_field(call, 'id'))} | "
                f"`{_md_escape(_tool_field(call, 'tool'))}` | {status} | "
                f"{_format_latency(_tool_field(call, 'latency_ms', 0.0))} | "
                f"{_md_escape(_tool_field(call, 'reason', ''))} | {error} |"
            )
    else:
        out.append("未调用外部工具。")
    out.append("")

    out.append("## 冲突与分歧")
    out.append("")
    if report.conflicts:
        out.extend(f"- {conflict}" for conflict in report.conflicts)
    else:
        out.append("无")
    out.append("")

    out.append("## 处置建议")
    out.append("")
    if report.recommended_actions:
        out.extend(
            f"{index}. {action}"
            for index, action in enumerate(report.recommended_actions, start=1)
        )
    else:
        out.append("无额外建议。")
    out.append("")

    out.append("## 备注")
    out.append("")
    if report.notes:
        out.extend(f"- {note}" for note in report.notes)
    else:
        out.append("无")
    out.append("")

    if report.analysis_steps:
        out.append("## 分析流水线")
        out.append("")
        out.append("| 阶段 | 步骤 | 耗时 | 说明 |")
        out.append("| --- | --- | --- | --- |")
        for step in report.analysis_steps:
            out.append(
                f"| {_md_escape(step.phase)} | {_md_escape(step.title)} | "
                f"{_format_latency(step.elapsed_ms)} | {_md_escape(step.detail)} |"
            )
        out.append("")

    out.append("---")
    out.append(
        f"发现与分析耗时 {_format_latency(report.latency_ms)}；"
        "所有结论均可追溯到证据 ID 或工具返回结果。"
    )
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# rich (optional)
# --------------------------------------------------------------------------- #


def _score_style(score: float) -> str:
    return f"bold {_score_color(score)}"


def render_rich(report: AnalysisReport) -> None:
    """Print a coloured report when ``rich`` is available, else plain text."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:  # pragma: no cover - exercised only without rich
        print(render_text(report))
        return

    if not isinstance(report, AnalysisReport):
        raise TypeError("render_rich expects an AnalysisReport")

    console = Console(highlight=False, soft_wrap=False)
    breakdown = report.score_breakdown
    action_colour = {
        "Block": "bold red",
        "Quarantine": "bold yellow",
        "Allow": "bold green",
    }.get(report.action, "bold white")

    title = Text("PhishHunter 钓鱼邮件分析报告", style="bold")
    console.print(Panel(title, border_style="blue", expand=False))

    header = Table.grid(padding=(0, 2))
    header.add_column(style="bold", no_wrap=True)
    header.add_column()
    header.add_row("邮件 ID", Text(_safe_str(report.email_id, "未知")))
    header.add_row("主题", Text(_safe_str(report.subject)))
    header.add_row("发件人", Text(_safe_str(report.sender)))
    header.add_row(
        "风险评分",
        Text(f"{report.risk_score:.1f} / 100  [{report.risk_level}]", style=_score_style(report.risk_score)),
    )
    header.add_row("处置建议", Text(_action_text(report.action), style=action_colour))
    header.add_row("置信度", Text(f"{report.confidence:.2f}"))
    header.add_row("分析耗时", Text(_format_latency(report.latency_ms)))
    header.add_row("生成时间", Text(_safe_str(report.generated_at)))
    engine = report.engine or {}
    if engine:
        header.add_row(
            "引擎",
            Text(
                f"{engine.get('mode', '')} / provider={engine.get('llm_provider', 'none')}"
                f" / model={engine.get('llm_model') or 'n/a'}"
                f" / planner={engine.get('planner', 'heuristic')}"
            ),
        )
    if report.injection_detected:
        header.add_row("提示注入", Text("已检测到（未执行其中指令）", style="bold"))
    console.print(header)
    console.rule()

    console.print(Text("摘要", style="bold"))
    console.print(Text(_safe_str(report.summary, "（无摘要）")))
    console.print()

    evidence = _ordered_evidence(report)
    console.print(Text(f"证据链 · {len(evidence)} 条", style="bold"))
    if evidence:
        table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        table.add_column("ID", no_wrap=True)
        table.add_column("极性", no_wrap=True)
        table.add_column("类别", no_wrap=True)
        table.add_column("严重度", justify="right", no_wrap=True)
        table.add_column("置信度", justify="right", no_wrap=True)
        table.add_column("标题 / 详情")
        for item in evidence:
            polarity_style = "green" if item.polarity == POLARITY_MITIGATING else "red"
            detail = Text()
            detail.append(_safe_str(item.title), style="bold")
            if item.detail:
                detail.append("\n")
                detail.append(_safe_str(item.detail))
            if item.tags:
                detail.append("\n")
                detail.append("标签：" + ", ".join(item.tags), style="dim")
            if item.source:
                detail.append("\n")
                detail.append("来源：" + item.source, style="dim")
            table.add_row(
                Text(_safe_str(item.id, "E???")),
                Text(_polarity_text(item), style=polarity_style),
                Text(_category_text(item.category)),
                Text(f"{item.severity:.2f}"),
                Text(f"{item.confidence:.2f}"),
                detail,
            )
        console.print(table)
    else:
        console.print(Text("未产生证据。", style="dim"))
    console.print()

    console.print(Text(f"推理过程 · {len(report.reasoning_steps)} 步", style="bold"))
    if report.reasoning_steps:
        for index, step in enumerate(report.reasoning_steps, start=1):
            console.print(Text(f"{index}. {step}"))
    else:
        console.print(Text("未提供推理步骤。", style="dim"))
    console.print()

    breakdown_table = Table(show_header=False, box=None, pad_edge=False)
    breakdown_table.add_column(style="cyan", no_wrap=True)
    breakdown_table.add_column()
    breakdown_table.add_row("原始证据分", f"{breakdown.raw_score:.1f}")
    breakdown_table.add_row("缓解扣减", _mitigation_text(breakdown.mitigation_points))
    breakdown_table.add_row(
        "策略下限",
        f"{breakdown.floor:.1f}" if breakdown.floor is not None else "无",
    )
    for reason in breakdown.floor_reasons or []:
        breakdown_table.add_row("  下限原因", reason)
    breakdown_table.add_row("下限前得分", f"{breakdown.pre_llm_score:.1f}")
    breakdown_table.add_row("模型调整", f"{breakdown.llm_adjustment:+.1f}")
    breakdown_table.add_row(
        "最终得分",
        Text(f"{breakdown.final_score:.1f} ({breakdown.risk_level})", style=_score_style(breakdown.final_score)),
    )
    console.print(Text("评分明细", style="bold"))
    console.print(breakdown_table)
    for category, contribution, cat_risk in _category_rows(report):
        console.print(
            Text(
                f"  {_pad(_category_text(category), 14)} {contribution:6.2f} 分"
                f"（类别风险系数 {cat_risk:.2f}）",
                style="dim",
            )
        )
    console.print()

    console.print(Text(f"工具调用 · {len(report.tool_calls)} 次", style="bold"))
    if report.tool_calls:
        tools_table = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
        tools_table.add_column("ID", no_wrap=True)
        tools_table.add_column("工具", no_wrap=True)
        tools_table.add_column("状态", no_wrap=True)
        tools_table.add_column("耗时", justify="right", no_wrap=True)
        tools_table.add_column("原因 / 错误")
        for call in report.tool_calls:
            ok = bool(_tool_field(call, "ok", True))
            detail = Text(_safe_str(_tool_field(call, "reason"), "（未记录原因）"))
            error = _safe_str(_tool_field(call, "error"), "")
            if error:
                detail.append("\n")
                detail.append("错误：" + error, style="red")
            tools_table.add_row(
                Text(_safe_str(_tool_field(call, "id"))),
                Text(_safe_str(_tool_field(call, "tool"))),
                Text("成功" if ok else "失败", style="green" if ok else "red"),
                Text(_format_latency(_tool_field(call, "latency_ms", 0.0))),
                detail,
            )
        console.print(tools_table)
    else:
        console.print(Text("未调用外部工具。", style="dim"))
    console.print()

    console.print(Text("冲突与分歧", style="bold"))
    if report.conflicts:
        for conflict in report.conflicts:
            console.print(Text(f"- {conflict}", style="yellow"))
    else:
        console.print(Text("无", style="dim"))
    console.print()

    console.print(Text("处置建议", style="bold"))
    if report.recommended_actions:
        for index, action in enumerate(report.recommended_actions, start=1):
            console.print(Text(f"{index}. {action}"))
    else:
        console.print(Text("无额外建议。", style="dim"))

    if report.notes:
        console.print()
        console.print(Text("备注", style="bold"))
        for note in report.notes:
            console.print(Text(f"- {note}", style="dim"))

    console.rule()
    console.print(
        Text(
            f"分析耗时 {_format_latency(report.latency_ms)} · "
            "所有结论均可追溯到证据 ID 或工具返回结果。",
            style="dim",
        )
    )


# --------------------------------------------------------------------------- #
# JSON
# --------------------------------------------------------------------------- #


def report_to_json(report: AnalysisReport | dict[str, Any], indent: int = 2) -> str:
    """Serialise a report (or an already-serialised dict) as UTF-8 JSON text."""
    if isinstance(report, AnalysisReport):
        payload: Any = report.to_dict()
    elif isinstance(report, dict):
        payload = report
    else:
        raise TypeError("report_to_json expects an AnalysisReport or dict")
    return json.dumps(payload, ensure_ascii=False, indent=indent, default=str)


__all__ = [
    "render_text",
    "render_rich",
    "render_markdown",
    "report_to_json",
]
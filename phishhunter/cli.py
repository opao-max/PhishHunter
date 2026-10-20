"""Command line entry point for PhishHunter.

The CLI is intentionally thin: parsing, file/stdin handling and predictable
exit codes live here; all analysis is delegated to the agent and all rendering
to :mod:`phishhunter.report`.

Exit codes
----------
0  success
2  invalid input / missing dependency / unusable environment
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import unicodedata
from pathlib import Path
from typing import Any, Sequence

from .config import DEFAULT_EMAIL_DIR, PROJECT_ROOT, Settings
from .models import AnalysisReport
from .report import render_rich, render_text, report_to_json

LLM_CHOICES = ("auto", "none", "mock", "openai", "anthropic")
PLANNER_CHOICES = ("heuristic", "llm")
PHISHING_LABELS = {"phishing", "phish", "malicious", "spam", "钓鱼"}
LEGIT_LABELS = {"legit", "legitimate", "benign", "normal", "正常", "合法"}


# --------------------------------------------------------------------------- #
# environment helpers
# --------------------------------------------------------------------------- #


def _configure_utf8() -> None:
    """Use UTF-8 for console output on Windows (cp936 would break reports)."""
    if os.name != "nt":
        return
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if not callable(reconfigure):
            continue
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding in {"utf8", "utf_8"}:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - stream already used
            pass


def _error(message: str) -> None:
    print(f"错误：{message}", file=sys.stderr)


def _warn(message: str) -> None:
    print(f"警告：{message}", file=sys.stderr)


def _display_width(text: str) -> int:
    width = 0
    for char in str(text):
        width += 2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1
    return width


def _pad(text: Any, width: int) -> str:
    text = str(text)
    return text + " " * max(0, width - _display_width(text))


# --------------------------------------------------------------------------- #
# settings / agent
# --------------------------------------------------------------------------- #


def _build_settings(args: argparse.Namespace) -> Settings:
    settings = Settings.from_env()
    provider = getattr(args, "llm", None)
    if provider:
        settings.llm_provider = str(provider).lower()
    planner = getattr(args, "planner", None)
    if planner:
        settings.planner = str(planner).lower()
    if getattr(args, "no_network", False):
        settings.allow_network = False
    return settings


def _analyze_email(email: dict[str, Any], args: argparse.Namespace) -> AnalysisReport:
    # Imported lazily so ``--help`` and test collection work even when the
    # optional tool/LLM subpackages are still being assembled.
    from .agent import PhishHunterAgent

    agent = PhishHunterAgent(settings=_build_settings(args))
    return agent.analyze(email)


# --------------------------------------------------------------------------- #
# input helpers
# --------------------------------------------------------------------------- #


def _read_input(path: str) -> str:
    if path == "-":
        buffer = getattr(sys.stdin, "buffer", None)
        if buffer is not None:
            return buffer.read().decode("utf-8", errors="replace")
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8")


def _parse_email(text: str) -> dict[str, Any]:
    payload = json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError("邮件 JSON 顶层必须是一个对象")
    # Accept both a raw email object and the web-style ``{"email": {...}}``.
    nested = payload.get("email")
    if isinstance(nested, dict) and not (
        {"headers", "body_text", "body_html"} & set(payload)
    ):
        payload = nested
    return payload


def _write_output(path: str, content: str) -> None:
    target = Path(path)
    if target.parent and str(target.parent) not in {"", "."}:
        target.parent.mkdir(parents=True, exist_ok=True)
    if not content.endswith("\n"):
        content += "\n"
    target.write_text(content, encoding="utf-8")


# --------------------------------------------------------------------------- #
# analyze
# --------------------------------------------------------------------------- #


def _cmd_analyze(args: argparse.Namespace) -> int:
    try:
        raw = _read_input(args.file)
    except FileNotFoundError:
        _error(f"找不到邮件文件：{args.file}")
        return 2
    except IsADirectoryError:
        _error(f"输入路径是目录，请提供 JSON 文件：{args.file}")
        return 2
    except UnicodeDecodeError as exc:
        _error(f"文件不是有效的 UTF-8 文本：{exc}")
        return 2
    except OSError as exc:
        _error(f"无法读取输入：{exc}")
        return 2

    if not raw.strip():
        _error("输入为空，请提供邮件 JSON 内容。")
        return 2

    try:
        email = _parse_email(raw)
    except json.JSONDecodeError as exc:
        _error(f"JSON 解析失败（第 {exc.lineno} 行，第 {exc.colno} 列）：{exc.msg}")
        return 2
    except ValueError as exc:
        _error(str(exc))
        return 2

    try:
        report = _analyze_email(email, args)
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _error(f"分析失败：{type(exc).__name__}: {exc}")
        return 2

    if args.json:
        content = report_to_json(report)
        print(content)
    else:
        content = render_text(report)
        render_rich(report)
    if args.output:
        try:
            _write_output(args.output, content)
        except OSError as exc:
            _error(f"无法写入输出文件 {args.output}：{exc}")
            return 2
        print(f"报告已写入：{args.output}", file=sys.stderr)
    return 0


# --------------------------------------------------------------------------- #
# demo
# --------------------------------------------------------------------------- #


def _verdict_correct(
    label: str, expected_action: str, action: str
) -> bool | None:
    """Apply the same tolerant policy used by the end-to-end tests.

    * explicit ``expected_action`` -> Block requires Block; Quarantine accepts
      Block/Quarantine; Allow requires Allow
    * ``label`` -> phishing must not be Allowed; legit should be Allowed
    * no metadata -> unknown
    """
    expected = (expected_action or "").strip().lower()
    if expected in {"block", "quarantine", "allow"}:
        if expected == "block":
            return action == "Block"
        if expected == "quarantine":
            return action in {"Block", "Quarantine"}
        return action == "Allow"

    normalized = (label or "").strip().lower()
    if normalized in PHISHING_LABELS:
        return action != "Allow"
    if normalized in LEGIT_LABELS:
        return action == "Allow"
    return None


def _demo_correct_text(correct: bool | None) -> str:
    if correct is True:
        return "是"
    if correct is False:
        return "否"
    return "-"


def _load_sample(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("顶层不是 JSON 对象")
    return data


def _cmd_demo(args: argparse.Namespace) -> int:
    email_dir = Path(os.getenv("PHISHHUNTER_EMAIL_DIR", str(DEFAULT_EMAIL_DIR)))
    if not email_dir.is_dir():
        print(f"未找到样例目录：{email_dir}", file=sys.stderr)
        print("提示：在 data/emails/ 下放置邮件 JSON 后重试。", file=sys.stderr)
        return 0

    files = sorted(email_dir.glob("*.json"))
    if args.limit and args.limit > 0:
        files = files[: args.limit]
    if not files:
        print(f"样例目录为空：{email_dir}", file=sys.stderr)
        print("提示：在 data/emails/ 下放置邮件 JSON 后重试。", file=sys.stderr)
        return 0

    try:
        from .agent import PhishHunterAgent

        agent = PhishHunterAgent(settings=_build_settings(args))
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _error(f"无法初始化分析引擎：{type(exc).__name__}: {exc}")
        return 2

    rows: list[dict[str, Any]] = []
    reports: list[tuple[dict[str, Any], AnalysisReport]] = []
    for path in files:
        try:
            data = _load_sample(path)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            _warn(f"跳过无法解析的样例 {path.name}：{exc}")
            continue
        try:
            report = agent.analyze(data)
        except Exception as exc:  # noqa: BLE001 - one sample must not kill demo
            _warn(f"跳过分析失败的样例 {path.name}：{type(exc).__name__}: {exc}")
            continue
        label = str(data.get("label") or "")
        expected = str(data.get("expected_action") or "")
        correct = _verdict_correct(label, expected, report.action)
        rows.append(
            {
                "id": report.email_id or path.stem,
                "filename": path.name,
                "subject": report.subject,
                "label": label,
                "expected_action": expected,
                "risk_score": report.risk_score,
                "risk_level": report.risk_level,
                "action": report.action,
                "correct": correct,
                "latency_ms": report.latency_ms,
            }
        )
        reports.append((data, report))

    if not rows:
        print("没有可用的样例分析结果。", file=sys.stderr)
        return 0

    phishing = [
        (data, report)
        for data, report in reports
        if str(data.get("label") or "").strip().lower() in PHISHING_LABELS
        or str(data.get("expected_action") or "").strip().lower() == "block"
    ]
    featured = phishing[0][1] if phishing else reports[0][1]

    if args.json:
        payload = {
            "samples": rows,
            "full_report": featured.to_dict() if featured else None,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    header = "  ".join(
        [
            _pad("邮件 ID", 22),
            _pad("期望", 12),
            _pad("得分", 7),
            _pad("动作", 12),
            _pad("正确", 5),
            "耗时",
        ]
    )
    print("PhishHunter 样例演示")
    print("=" * _display_width(header))
    print(header)
    print("-" * _display_width(header))
    for data, report in reports:
        label = str(data.get("label") or "")
        expected = str(data.get("expected_action") or "")
        shown_expectation = label or expected or "-"
        correct = _verdict_correct(label, expected, report.action)
        print(
            "  ".join(
                [
                    _pad(report.email_id or "-", 22),
                    _pad(shown_expectation, 12),
                    _pad(f"{report.risk_score:.1f}", 7),
                    _pad(report.action, 12),
                    _pad(_demo_correct_text(correct), 5),
                    f"{report.latency_ms:.1f} ms",
                ]
            )
        )
    print("-" * _display_width(header))
    print(
        f"共 {len(rows)} 封；"
        f"拦截 {sum(1 for row in rows if row['action'] == 'Block')}，"
        f"隔离 {sum(1 for row in rows if row['action'] == 'Quarantine')}，"
        f"放行 {sum(1 for row in rows if row['action'] == 'Allow')}。"
    )
    print()
    print("首封钓鱼样本完整报告")
    print()
    render_rich(featured)
    return 0


# --------------------------------------------------------------------------- #
# evaluate
# --------------------------------------------------------------------------- #


def _cmd_evaluate(args: argparse.Namespace) -> int:
    root = str(PROJECT_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        from scripts import evaluate  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _error(
            "无法加载评估脚本 scripts/evaluate.py："
            f"{type(exc).__name__}: {exc}"
        )
        return 2

    argv = ["--json"] if args.json else []
    try:
        code = evaluate.main(argv)
    except SystemExit as exc:  # pragma: no cover - defensive
        code = exc.code
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _error(f"评估执行失败：{type(exc).__name__}: {exc}")
        return 2
    try:
        return int(code or 0)
    except (TypeError, ValueError):
        return 0


# --------------------------------------------------------------------------- #
# serve
# --------------------------------------------------------------------------- #


def _cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        _error("未安装 uvicorn。请先执行：pip install fastapi uvicorn")
        return 2
    try:
        uvicorn.run(
            "phishhunter.web.app:app",
            host=args.host,
            port=args.port,
            log_level="info",
        )
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        _error(f"Web 服务启动失败：{type(exc).__name__}: {exc}")
        return 2
    return 0


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    parser = argparse.ArgumentParser(
        prog="phishhunter",
        description="PhishHunter：证据驱动的多模态钓鱼邮件检测智能体",
    )
    parser.add_argument(
        "--version", action="version", version=f"PhishHunter {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    analyze = subparsers.add_parser(
        "analyze", help="分析单封邮件（JSON 文件或标准输入）"
    )
    analyze.add_argument("file", metavar="FILE|-", help="邮件 JSON 文件；使用 - 从标准输入读取")
    analyze.add_argument("--json", action="store_true", help="输出 JSON 报告")
    analyze.add_argument("--output", metavar="PATH", help="同时将报告写入文件")
    analyze.add_argument(
        "--llm", choices=LLM_CHOICES, default=None, help="覆盖 LLM 提供方（默认读取环境变量）"
    )
    analyze.add_argument(
        "--planner", choices=PLANNER_CHOICES, default=None, help="规划器类型（默认 heuristic）"
    )
    analyze.add_argument(
        "--no-network", action="store_true", help="强制离线模式（禁用任何网络工具）"
    )
    analyze.set_defaults(handler=_cmd_analyze)

    demo = subparsers.add_parser("demo", help="批量分析 data/emails 下的样例邮件")
    demo.add_argument("--limit", type=int, default=0, metavar="N", help="最多分析 N 封（0 表示全部）")
    demo.add_argument("--json", action="store_true", help="以 JSON 输出汇总与完整报告")
    demo.add_argument(
        "--llm", choices=LLM_CHOICES, default="mock", help="LLM 提供方（demo 默认 mock）"
    )
    demo.add_argument(
        "--planner", choices=PLANNER_CHOICES, default=None, help="规划器类型"
    )
    demo.add_argument("--no-network", action="store_true", help="强制离线模式")
    demo.set_defaults(handler=_cmd_demo)

    evaluate = subparsers.add_parser("evaluate", help="运行离线评估并生成报告")
    evaluate.add_argument("--json", action="store_true", help="以 JSON 输出指标")
    evaluate.set_defaults(handler=_cmd_evaluate)

    serve = subparsers.add_parser("serve", help="启动 Web 控制台（FastAPI）")
    serve.add_argument("--host", default="127.0.0.1", help="监听地址（默认 127.0.0.1）")
    serve.add_argument("--port", type=int, default=8000, help="监听端口（默认 8000）")
    serve.set_defaults(handler=_cmd_serve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    _configure_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 0
    return int(handler(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
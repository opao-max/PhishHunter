"""Offline evaluation harness for the PhishHunter sample corpus.

The harness runs the deterministic agent (mock LLM, heuristic planner) over
every JSON sample in ``data/emails`` and reports detection quality together
with latency.  Positive class = phishing; a sample is considered "flagged"
when the agent recommends ``Block`` or ``Quarantine``.

Exit code is 0 only when all quality gates pass, which lets CI fail on a
regression::

    python scripts/evaluate.py            # human-readable summary
    python scripts/evaluate.py --json     # machine-readable metrics
"""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

EVAL_ROOT = Path(__file__).resolve().parents[1]
if str(EVAL_ROOT) not in sys.path:
    sys.path.insert(0, str(EVAL_ROOT))

from phishhunter.agent import PhishHunterAgent  # noqa: E402
from phishhunter.config import DEFAULT_EMAIL_DIR, Settings  # noqa: E402

REPORT_DIR = EVAL_ROOT / "reports"
DETECTED_ACTIONS = frozenset({"Block", "Quarantine"})

# Quality gates.  Accuracy and recall protect detection; FPR protects the
# business from alert fatigue caused by blocking legitimate mail.
THRESHOLDS: dict[str, float] = {
    "accuracy": 0.85,
    "recall": 0.85,
    "false_positive_rate": 0.20,
}


# --------------------------------------------------------------------------- #
# loading / statistics helpers
# --------------------------------------------------------------------------- #


def load_samples(directory: str | Path) -> list[dict[str, Any]]:
    """Load every ``*.json`` sample in deterministic filename order."""
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError(f"样本目录不存在: {directory}")
    samples: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"样本 JSON 解析失败 {path.name}: {exc}") from exc
        if isinstance(data, dict):
            data.setdefault("_source_file", path.name)
            samples.append(data)
    return samples


def _ratio(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _percentile(values: Iterable[float], percentile: float) -> float:
    """Nearest-rank percentile (no external dependencies)."""
    ordered = sorted(float(v) for v in values)
    if not ordered:
        return 0.0
    rank = max(1, math.ceil(percentile / 100.0 * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def _latency_summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0, "max": 0.0}
    return {
        "mean": round(statistics.fmean(values), 2),
        "median": round(statistics.median(values), 2),
        "p95": round(_percentile(values, 95), 2),
        "max": round(max(values), 2),
    }


# --------------------------------------------------------------------------- #
# evaluation
# --------------------------------------------------------------------------- #


def _evaluate_case(sample: dict[str, Any], agent: Any) -> dict[str, Any]:
    label = str(sample.get("label") or "").strip().lower()
    expected_action = str(sample.get("expected_action") or "").strip()
    row: dict[str, Any] = {
        "id": str(sample.get("id") or sample.get("_source_file") or "unknown"),
        "filename": str(sample.get("_source_file") or ""),
        "subject": str((sample.get("headers") or {}).get("subject") or ""),
        "label": label,
        "expected_action": expected_action,
        "adversarial": bool(sample.get("adversarial")),
    }
    try:
        report = agent.analyze(sample)
    except Exception as exc:  # noqa: BLE001 - one bad sample must not stop the run
        row.update(
            {
                "action": "Error",
                "risk_score": 0.0,
                "risk_level": "Error",
                "detected": False,
                "correct": False,
                "latency_ms": 0.0,
                "evidence_count": 0,
                "injection_detected": False,
                "floor": None,
                "floor_reasons": [],
                "top_evidence": "",
                "error": f"{type(exc).__name__}: {exc}",
            }
        )
        return row

    detected = report.action in DETECTED_ACTIONS
    if label == "phishing":
        correct: bool | None = detected
    elif label == "legit":
        correct = not detected
    else:
        correct = None

    top_risk = report.top_evidence
    row.update(
        {
            "action": report.action,
            "risk_score": round(float(report.risk_score), 2),
            "risk_level": report.risk_level,
            "detected": detected,
            "correct": correct,
            "latency_ms": round(float(report.latency_ms), 2),
            "evidence_count": len(report.evidence_chain),
            "injection_detected": bool(report.injection_detected),
            "floor": report.score_breakdown.floor,
            "floor_reasons": list(report.score_breakdown.floor_reasons),
            "top_evidence": top_risk[0].title if top_risk else "",
            "error": "",
        }
    )
    return row


def evaluate(samples: list[dict[str, Any]], agent: Any) -> dict[str, Any]:
    """Run the agent over all samples and compute corpus-level metrics."""
    rows = [_evaluate_case(sample, agent) for sample in samples]

    tp = fp = tn = fn = 0
    labelled = 0
    for row in rows:
        if row["label"] not in {"phishing", "legit"}:
            continue
        labelled += 1
        if row["label"] == "phishing" and row["detected"]:
            tp += 1
        elif row["label"] == "phishing":
            fn += 1
        elif row["detected"]:
            fp += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    accuracy = _ratio(tp + tn, total)
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = _ratio(2 * precision * recall, precision + recall)
    false_positive_rate = _ratio(fp, fp + tn)
    false_negative_rate = _ratio(fn, tp + fn)
    latency = _latency_summary([row["latency_ms"] for row in rows])

    checks = {
        "accuracy": accuracy >= THRESHOLDS["accuracy"],
        "recall": recall >= THRESHOLDS["recall"],
        "false_positive_rate": false_positive_rate <= THRESHOLDS["false_positive_rate"],
    }
    failures = [
        f"{name} {'>=' if name != 'false_positive_rate' else '<='} "
        f"{THRESHOLDS[name]:.2f} 未达标（实际 {value:.4f}）"
        for name, value in (
            ("accuracy", accuracy),
            ("recall", recall),
            ("false_positive_rate", false_positive_rate),
        )
        if not checks[name]
    ]
    if total == 0:
        failures.append("没有带 label 的样本，无法评估")

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "config": {
            "llm_provider": "mock",
            "planner": "heuristic",
            "network": "disabled",
            "detected_actions": sorted(DETECTED_ACTIONS),
            "positive_class": "phishing",
        },
        "thresholds": dict(THRESHOLDS),
        "metrics": {
            "samples": len(rows),
            "labelled": labelled,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_positive_rate": round(false_positive_rate, 4),
            "false_negative_rate": round(false_negative_rate, 4),
            "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
            "latency_ms": latency,
        },
        "checks": checks,
        "passed": all(checks.values()) and total > 0,
        "failures": failures,
        "per_case": rows,
    }


# --------------------------------------------------------------------------- #
# rendering / persistence
# --------------------------------------------------------------------------- #


def _render_text(result: dict[str, Any]) -> str:
    metrics = result["metrics"]
    cm = metrics["confusion_matrix"]
    lines = [
        "PhishHunter 离线评估",
        "=" * 72,
        (
            f"样本 {metrics['samples']} 封（有标签 {metrics['labelled']} 封） | "
            f"准确率 {metrics['accuracy']:.2%} | 精确率 {metrics['precision']:.2%} | "
            f"召回率 {metrics['recall']:.2%} | F1 {metrics['f1']:.2%}"
        ),
        (
            f"误报率 FPR {metrics['false_positive_rate']:.2%} | "
            f"漏报率 FNR {metrics['false_negative_rate']:.2%}"
        ),
        f"混淆矩阵 TP={cm['tp']} FP={cm['fp']} TN={cm['tn']} FN={cm['fn']}",
        (
            f"延迟(ms) 均值 {metrics['latency_ms']['mean']:.2f} | "
            f"中位数 {metrics['latency_ms']['median']:.2f} | "
            f"P95 {metrics['latency_ms']['p95']:.2f}"
        ),
        "",
        f"{'id':<12}{'label':<10}{'expected':<12}{'action':<12}{'score':>7}{'ok':>5}{'ms':>9}",
        "-" * 72,
    ]
    for row in result["per_case"]:
        ok = "Y" if row["correct"] else ("-" if row["correct"] is None else "N")
        lines.append(
            f"{row['id']:<12}{row['label']:<10}{row['expected_action']:<12}"
            f"{row['action']:<12}{row['risk_score']:>7.1f}{ok:>5}{row['latency_ms']:>9.2f}"
        )
    lines.append("")
    if result["passed"]:
        lines.append("质量门槛：全部通过")
    else:
        lines.append("质量门槛：未通过")
        for failure in result["failures"]:
            lines.append(f"  - {failure}")
    return "\n".join(lines)


def _render_markdown(result: dict[str, Any]) -> str:
    metrics = result["metrics"]
    cm = metrics["confusion_matrix"]
    lines = [
        "# PhishHunter 离线评估报告",
        "",
        f"- 生成时间：`{result['generated_at']}`",
        "- 运行模式：`mock LLM + heuristic planner`（完全离线、确定性）",
        "- 正类：`phishing`；`Block` 与 `Quarantine` 均视为检出",
        "",
        "## 总体指标",
        "",
        "| 指标 | 数值 |",
        "| --- | ---: |",
        f"| 样本数 | {metrics['samples']} |",
        f"| 有标签样本 | {metrics['labelled']} |",
        f"| 准确率 Accuracy | {metrics['accuracy']:.2%} |",
        f"| 精确率 Precision | {metrics['precision']:.2%} |",
        f"| 召回率 Recall | {metrics['recall']:.2%} |",
        f"| F1 | {metrics['f1']:.2%} |",
        f"| 误报率 FPR | {metrics['false_positive_rate']:.2%} |",
        f"| 漏报率 FNR | {metrics['false_negative_rate']:.2%} |",
        "",
        "## 混淆矩阵",
        "",
        "| | 预测为钓鱼 | 预测为正常 |",
        "| --- | ---: | ---: |",
        f"| 实际钓鱼 | TP={cm['tp']} | FN={cm['fn']} |",
        f"| 实际正常 | FP={cm['fp']} | TN={cm['tn']} |",
        "",
        "## 延迟",
        "",
        "| 均值 (ms) | 中位数 (ms) | P95 (ms) | 最大 (ms) |",
        "| ---: | ---: | ---: | ---: |",
        (
            f"| {metrics['latency_ms']['mean']:.2f} | {metrics['latency_ms']['median']:.2f} "
            f"| {metrics['latency_ms']['p95']:.2f} | {metrics['latency_ms']['max']:.2f} |"
        ),
        "",
        "## 质量门槛",
        "",
        "| 门槛 | 要求 | 实际 | 结果 |",
        "| --- | ---: | ---: | --- |",
        (
            f"| Accuracy | >= {result['thresholds']['accuracy']:.2f} | "
            f"{metrics['accuracy']:.4f} | {'通过' if result['checks']['accuracy'] else '未通过'} |"
        ),
        (
            f"| Recall | >= {result['thresholds']['recall']:.2f} | "
            f"{metrics['recall']:.4f} | {'通过' if result['checks']['recall'] else '未通过'} |"
        ),
        (
            f"| FPR | <= {result['thresholds']['false_positive_rate']:.2f} | "
            f"{metrics['false_positive_rate']:.4f} | "
            f"{'通过' if result['checks']['false_positive_rate'] else '未通过'} |"
        ),
        "",
        f"**总体结果：{'通过' if result['passed'] else '未通过'}**",
        "",
        "## 逐样本结果",
        "",
        "| ID | 标签 | 期望动作 | 实际动作 | 风险分 | 证据数 | 做法正确 | 延迟 (ms) | 关键证据 |",
        "| --- | --- | --- | --- | ---: | ---: | --- | ---: | --- |",
    ]
    for row in result["per_case"]:
        if row["correct"] is None:
            ok = "-"
        else:
            ok = "是" if row["correct"] else "否"
        top = (row["top_evidence"] or "").replace("|", "/")
        lines.append(
            f"| {row['id']} | {row['label']} | {row['expected_action']} | {row['action']} "
            f"| {row['risk_score']:.1f} | {row['evidence_count']} | {ok} "
            f"| {row['latency_ms']:.2f} | {top} |"
        )
    lines.append("")
    if not result["passed"]:
        lines.append("未达标项：")
        lines.extend(f"- {failure}" for failure in result["failures"])
        lines.append("")
    return "\n".join(lines)


def write_reports(result: dict[str, Any], output_dir: str | Path) -> tuple[Path, Path]:
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "evaluation.json"
    markdown_path = output_dir / "evaluation.md"
    json_path.write_text(
        json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    markdown_path.write_text(_render_markdown(result), encoding="utf-8")
    return json_path, markdown_path


# --------------------------------------------------------------------------- #
# entry point
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the offline PhishHunter agent over the sample corpus."
    )
    parser.add_argument(
        "--json", action="store_true", help="print metrics as JSON instead of text"
    )
    parser.add_argument(
        "--emails-dir",
        default=str(DEFAULT_EMAIL_DIR),
        help="directory containing sample JSON files",
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPORT_DIR),
        help="directory for evaluation.json / evaluation.md",
    )
    return parser


def _configure_stdout_encoding() -> None:
    """Prefer UTF-8 when output is redirected (Git Bash, CI logs)."""
    stream = sys.stdout
    if stream is None or stream.isatty():
        return
    try:
        stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except (AttributeError, ValueError, OSError):
        pass


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_stdout_encoding()

    settings = Settings(
        llm_provider="mock",
        planner="heuristic",
        allow_network=False,
        mock_intel=True,
    )
    agent = PhishHunterAgent(settings=settings)
    samples = load_samples(args.emails_dir)
    result = evaluate(samples, agent)
    json_path, markdown_path = write_reports(result, args.output_dir)

    if args.json:
        print(json.dumps(result["metrics"], ensure_ascii=False, indent=2))
    else:
        print(_render_text(result))
        print(f"\n报告已写入: {json_path}")
        print(f"报告已写入: {markdown_path}")

    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
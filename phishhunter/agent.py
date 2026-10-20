"""PhishHunter agent: Perceive -> Plan -> Act -> Judge -> Report.

The orchestration is intentionally explicit rather than hidden inside a
framework.  Every decision is traceable: static detectors and tools produce
structured ``Evidence``; the scorer fuses it deterministically; the LLM only
adds bounded, citation-backed judgement.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any

from .config import Settings
from .detectors import run_static_detectors
from .models import (
    POLARITY_MITIGATING,
    AnalysisReport,
    AnalysisStep,
    AnalystOutput,
    EmailMessage,
    Evidence,
    ScoreBreakdown,
    ToolResult,
)
from .planner import HeuristicPlanner, LLMPlanner, Plan
from .scoring import (
    apply_llm_adjustment,
    recommend_action,
    risk_level_for,
    score_evidence,
)

VERSION = "1.0.0"


class PhishHunterAgent:
    """A multi-modal, evidence-first phishing triage agent."""

    def __init__(
        self,
        settings: Settings | None = None,
        registry: Any = None,
        provider: Any = None,
        planner: Any = None,
        analyst: Any = None,
    ) -> None:
        self.settings = settings or Settings.from_env()

        if registry is None:
            from .tools import build_default_registry

            registry = build_default_registry(self.settings.resolved_intel_path())
        self.registry = registry

        from .llm.factory import build_analyst, build_provider

        self.provider = provider if provider is not None else build_provider(self.settings)
        self.analyst = analyst if analyst is not None else build_analyst(
            self.settings, self.provider
        )

        if planner is not None:
            self.planner = planner
        elif self.settings.planner == "llm" and self.provider is not None:
            self.planner = LLMPlanner(self.provider, self.settings)
        else:
            self.planner = HeuristicPlanner(self.settings)

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #

    def analyze(self, email_input: EmailMessage | dict[str, Any]) -> AnalysisReport:
        started = time.perf_counter()
        notes: list[str] = []
        steps: list[AnalysisStep] = []

        if not isinstance(email_input, (EmailMessage, dict)):
            raise TypeError(
                "email_input must be an EmailMessage or a dict, "
                f"got {type(email_input).__name__}"
            )
        email = (
            email_input
            if isinstance(email_input, EmailMessage)
            else EmailMessage.from_dict(email_input)
        )

        t = time.perf_counter()
        static_evidence, detector_errors = run_static_detectors(email)
        notes.extend(f"静态检测器失败：{err}" for err in detector_errors)
        self._step(
            steps,
            "perceive",
            "感知：解析并静态检测邮件",
            (
                f"解析出 {len(email.links)} 个链接、{len(email.attachments)} 个附件、"
                f"{len(email.images)} 张图片；静态检测产生 {len(static_evidence)} 条证据。"
            ),
            t,
            {
                "links": len(email.links),
                "attachments": len(email.attachments),
                "images": len(email.images),
                "detector_errors": detector_errors,
            },
        )

        # ------------------------------------------------------------------
        # PLAN
        # ------------------------------------------------------------------
        t = time.perf_counter()
        plan: Plan = self.planner.plan(email, static_evidence, self.registry)
        notes.extend(plan.notes)
        self._step(
            steps,
            "plan",
            "规划：选择调查工具",
            (
                f"规划策略 {plan.strategy}，计划调用 {len(plan.calls)} 个工具："
                + (", ".join(plan.tool_names) if plan.tool_names else "无")
            ),
            t,
            {"strategy": plan.strategy, "tools": plan.tool_names},
        )

        # ------------------------------------------------------------------
        # ACT
        # ------------------------------------------------------------------
        t = time.perf_counter()
        results: list[ToolResult] = self.registry.execute_many(
            plan.calls,
            timeout_s=self.settings.tool_timeout_s,
            max_workers=min(4, max(1, len(plan.calls))) if plan.calls else 1,
        )
        tool_call_log: list[dict[str, Any]] = []
        tool_evidence: list[Evidence] = []
        failed = 0
        for call, result in zip(plan.calls, results):
            if not result.ok:
                failed += 1
                notes.append(f"工具 {call.tool} 失败：{result.error}")
            for item in result.evidence:
                if not item.source:
                    item.source = f"tool:{call.tool}"
                tool_evidence.append(item)
            tool_call_log.append(
                {
                    "id": call.id,
                    "tool": call.tool,
                    "params": _redact_params(call.params),
                    "reason": call.reason,
                    "ok": result.ok,
                    "latency_ms": round(result.latency_ms, 2),
                    "error": result.error,
                    "data_summary": _summarize_tool_data(result.data),
                    "data": result.data,
                    "evidence_ids": [],
                }
            )
        self._step(
            steps,
            "act",
            "行动：执行外部调查",
            (
                f"执行 {len(results)} 个工具调用，成功 {len(results) - failed}，失败 {failed}；"
                f"新增 {len(tool_evidence)} 条工具证据。"
            ),
            t,
            {"failed": failed, "evidence": len(tool_evidence)},
        )

        # ------------------------------------------------------------------
        # Evidence assembly + deterministic score
        # ------------------------------------------------------------------
        evidence = self._dedupe(static_evidence + tool_evidence)
        self._assign_ids(evidence)
        id_by_object = {id(item): item.id for item in evidence}
        for call, result, log in zip(plan.calls, results, tool_call_log):
            log["evidence_ids"] = [
                id_by_object[id(item)]
                for item in result.evidence
                if id(item) in id_by_object
            ]

        t = time.perf_counter()
        breakdown = score_evidence(
            evidence,
            block_threshold=self.settings.block_threshold,
            quarantine_threshold=self.settings.quarantine_threshold,
        )
        self._step(
            steps,
            "judge",
            "判断：确定性证据融合",
            (
                f"证据加权得分 {breakdown.raw_score}，缓解扣减 {breakdown.mitigation_points}，"
                f"策略下限 {breakdown.floor if breakdown.floor is not None else '无'}。"
            ),
            t,
            {
                "raw_score": breakdown.raw_score,
                "floor": breakdown.floor,
                "category_scores": breakdown.category_scores,
            },
        )

        # ------------------------------------------------------------------
        # JUDGE: LLM / heuristic analyst (advisory, bounded)
        # ------------------------------------------------------------------
        t = time.perf_counter()
        analyst_output = self._run_analyst(email, evidence, breakdown, notes)
        valid_ids = {item.id for item in evidence}
        adjustment = apply_llm_adjustment(
            breakdown,
            analyst_output.suggested_score,
            cited_ids=analyst_output.cited_evidence_ids,
            valid_ids=valid_ids,
            llm_confidence=analyst_output.confidence,
            max_delta=self.settings.llm_max_adjustment,
        )
        action = recommend_action(
            breakdown.final_score,
            self.settings.block_threshold,
            self.settings.quarantine_threshold,
        )
        breakdown.risk_level = risk_level_for(
            breakdown.final_score,
            self.settings.block_threshold,
            self.settings.quarantine_threshold,
        )
        self._step(
            steps,
            "judge",
            "判断：模型综合分析与策略校验",
            (
                f"分析器 {analyst_output.provider}/{analyst_output.model or 'n/a'}，"
                f"引用证据 {len(analyst_output.cited_evidence_ids)} 条，"
                f"评分调整 {adjustment:+.1f}，最终 {breakdown.final_score} 分。"
            ),
            t,
            {"adjustment": adjustment, "cited": analyst_output.cited_evidence_ids},
        )

        injection_detected = any(
            item.polarity != POLARITY_MITIGATING
            and item.category == "prompt_injection"
            for item in evidence
        ) or bool(analyst_output.injection_suspected)

        conflicts = list(dict.fromkeys(analyst_output.conflicts))
        if analyst_output.suggested_score is not None:
            suggested_action = recommend_action(
                analyst_output.suggested_score,
                self.settings.block_threshold,
                self.settings.quarantine_threshold,
            )
            if suggested_action != action:
                conflicts.append(
                    f"模型建议动作 {suggested_action} 与最终策略动作 {action} 不一致，"
                    "已按证据评分与下限策略执行。"
                )
            if breakdown.floor is not None and analyst_output.suggested_score < breakdown.floor:
                conflicts.append(
                    f"模型建议分 {analyst_output.suggested_score:.1f} 低于关键证据下限 "
                    f"{breakdown.floor:.0f}，下限优先。"
                )
            if abs(analyst_output.suggested_score - breakdown.pre_llm_score) > 20:
                conflicts.append(
                    f"模型建议分与确定性评分差异较大（{analyst_output.suggested_score:.1f} vs "
                    f"{breakdown.pre_llm_score:.1f}），调整幅度已限制在 ±"
                    f"{self.settings.llm_max_adjustment:.0f}。"
                )
        if adjustment:
            notes.append(f"LLM 评分调整 {adjustment:+.1f}（引用证据 {len(analyst_output.cited_evidence_ids)} 条）。")

        summary, summary_conflict = self._summary(
            email, evidence, breakdown, action, analyst_output
        )
        if summary_conflict:
            conflicts.append(summary_conflict)
            notes.append(summary_conflict)
        conflicts = list(dict.fromkeys(conflicts))
        reasoning = self._reasoning_steps(
            email, evidence, breakdown, action, analyst_output, injection_detected
        )
        recommended = self._recommended_actions(action, evidence)

        latency_ms = (time.perf_counter() - started) * 1000
        self._step(
            steps,
            "report",
            "报告：生成证据链与处置建议",
            f"风险 {breakdown.final_score}/100（{breakdown.risk_level}），建议 {action}。",
            started,
            {"action": action, "risk_score": breakdown.final_score},
        )

        engine = {
            "version": VERSION,
            "mode": (
                "offline-mock"
                if self.provider is None
                or getattr(self.provider, "name", "") in {"mock", "none"}
                else "hybrid-llm"
            ),
            "llm_provider": getattr(self.provider, "name", "none"),
            "llm_model": getattr(self.provider, "model", ""),
            "llm_active": self.provider is not None,
            "planner": plan.strategy,
            "planner_requested": self.settings.planner,
            "intel": "mock" if self.settings.mock_intel else "live",
            "thresholds": self.settings.threshold_labels(),
            "tool_budget": self.settings.max_tool_calls,
        }

        return AnalysisReport(
            email_id=email.id,
            subject=email.subject,
            sender=email.sender_raw,
            risk_score=breakdown.final_score,
            risk_level=breakdown.risk_level,
            action=action,
            confidence=breakdown.confidence,
            summary=summary,
            evidence_chain=sorted(
                evidence,
                key=lambda e: (e.polarity != "risk", -e.weight()),
            ),
            reasoning_steps=reasoning,
            score_breakdown=breakdown,
            tool_calls=tool_call_log,
            analysis_steps=steps,
            conflicts=conflicts,
            injection_detected=injection_detected,
            recommended_actions=recommended,
            engine=engine,
            latency_ms=round(latency_ms, 2),
            email_snapshot=email.to_dict(),
            notes=notes,
        )

    def analyze_file(self, path: str | Path) -> AnalysisReport:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.analyze(data)

    def analyze_many(self, emails: list[dict[str, Any]]) -> list[AnalysisReport]:
        return [self.analyze(item) for item in emails]

    # ------------------------------------------------------------------ #
    # internals
    # ------------------------------------------------------------------ #

    def _run_analyst(
        self,
        email: EmailMessage,
        evidence: list[Evidence],
        breakdown: ScoreBreakdown,
        notes: list[str],
    ) -> AnalystOutput:
        try:
            output = self.analyst.analyze(email, evidence, breakdown)
            if not isinstance(output, AnalystOutput):
                raise TypeError("analyst returned unexpected type")
            return output
        except Exception as exc:  # noqa: BLE001 - analyst failure is non-fatal
            notes.append(f"分析器失败，回退到确定性推理：{type(exc).__name__}: {exc}")
            return AnalystOutput(
                summary="",
                reasoning_steps=[],
                cited_evidence_ids=[],
                suggested_score=None,
                confidence=breakdown.confidence,
                provider="fallback",
                valid=False,
            )

    @staticmethod
    def _dedupe(evidence: list[Evidence]) -> list[Evidence]:
        best: dict[tuple[str, str, str], Evidence] = {}
        order: list[tuple[str, str, str]] = []
        for item in evidence:
            key = (item.category, item.title.strip(), item.detail.strip())
            # Detector and tool often describe the same QR payload with
            # different titles; key on the IOC so risk is not double-counted.
            if "qr_payload" in item.tags:
                payload = (
                    item.raw.get("qr_payload")
                    or item.raw.get("qr_url")
                    or item.raw.get("url")
                )
                if payload:
                    key = ("image", "qr_payload", str(payload).lower())
            if key not in best:
                best[key] = item
                order.append(key)
            elif item.weight() > best[key].weight():
                best[key] = item
        return [best[key] for key in order]

    @staticmethod
    def _assign_ids(evidence: list[Evidence]) -> None:
        for index, item in enumerate(evidence, start=1):
            item.id = f"E{index:03d}"

    @staticmethod
    def _step(
        steps: list[AnalysisStep],
        phase: str,
        title: str,
        detail: str,
        started: float,
        data: dict[str, Any] | None = None,
    ) -> None:
        steps.append(
            AnalysisStep(
                phase=phase,
                title=title,
                detail=detail,
                elapsed_ms=round((time.perf_counter() - started) * 1000, 2),
                data=data or {},
            )
        )

    def _summary(
        self,
        email: EmailMessage,
        evidence: list[Evidence],
        breakdown: ScoreBreakdown,
        action: str,
        analyst: AnalystOutput,
    ) -> tuple[str, str | None]:
        """Return ``(summary, rejection_reason)``.

        The model's prose is only accepted when it cites real evidence, does
        not invent IOCs, and does not contradict the deterministic action.
        Otherwise the authoritative deterministic summary is used.
        """
        fallback = self._fallback_summary(evidence, breakdown, action)
        if not (analyst.valid and analyst.summary.strip()):
            return fallback, None
        if not analyst.cited_evidence_ids:
            return fallback, "模型摘要未引用任何有效证据，已回退到确定性摘要。"
        if not self._summary_facts_grounded(analyst.summary, email, evidence):
            return fallback, "模型摘要包含证据/工具结果中不存在的 IOC，已回退到确定性摘要。"
        if not self._summary_action_consistent(analyst.summary, action):
            return fallback, "模型摘要与最终处置动作不一致，已回退到确定性摘要。"
        return analyst.summary.strip(), None

    @staticmethod
    def _fallback_summary(
        evidence: list[Evidence], breakdown: ScoreBreakdown, action: str
    ) -> str:
        risks = sorted(
            [e for e in evidence if e.polarity != POLARITY_MITIGATING],
            key=lambda e: e.weight(),
            reverse=True,
        )
        if action == "Block":
            lead = "、".join(e.title for e in risks[:2]) or "多项高风险信号"
            return (
                f"该邮件综合风险 {breakdown.final_score}/100，"
                f"关键证据为「{lead}」，达到自动拦截阈值，建议直接阻断。"
            )
        if action == "Quarantine":
            lead = "、".join(e.title for e in risks[:2]) or "可疑信号"
            return (
                f"该邮件综合风险 {breakdown.final_score}/100，"
                f"存在「{lead}」等待核实信号，建议隔离并人工复核。"
            )
        return (
            f"该邮件综合风险 {breakdown.final_score}/100，"
            "未发现足以拦截的确凿证据，建议正常投递并保留审计记录。"
        )

    @staticmethod
    def _summary_facts_grounded(
        summary: str, email: EmailMessage, evidence: list[Evidence]
    ) -> bool:
        """Reject model prose that introduces IOCs absent from the evidence."""
        patterns = (
            r"https?://[^\s，。；、）)\]\}]+",
            r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
            r"\b\d{1,3}(?:\.\d{1,3}){3}\b",
            r"\b[a-fA-F0-9]{32,64}\b",
            r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
        )
        tokens: set[str] = set()
        for pattern in patterns:
            for match in re.finditer(pattern, summary, re.IGNORECASE):
                token = match.group(0).strip().rstrip(".,;:!?)]}，。；：！？）").lower()
                if token:
                    tokens.add(token)
        if not tokens:
            return True

        corpus_parts = [email.from_domain, email.reply_to_domain, email.subject]
        for item in evidence:
            corpus_parts.append(f"{item.title} {item.detail}")
            try:
                corpus_parts.append(json.dumps(item.raw, ensure_ascii=False, default=str))
            except (TypeError, ValueError):
                pass
        corpus = "\n".join(part for part in corpus_parts if part).lower()
        for token in tokens:
            if token not in corpus:
                return False
        return True

    @staticmethod
    def _line_contradicts_evidence(
        line: str, evidence: list[Evidence], email: EmailMessage
    ) -> bool:
        """Drop model claims contradicted by deterministic evidence."""
        text = (line or "").lower()
        tags = {tag for item in evidence if item.polarity != POLARITY_MITIGATING for tag in item.tags}
        # An "old domain" mitigation only matters if it is about this sender.
        sender_old = False
        for item in evidence:
            if item.polarity != POLARITY_MITIGATING:
                continue
            if "established_domain" not in item.tags:
                continue
            try:
                raw = json.dumps(item.raw, ensure_ascii=False)
            except (TypeError, ValueError):
                raw = ""
            if email.from_domain and email.from_domain in raw.lower():
                sender_old = True
                break
        age_claim = any(
            phrase in text
            for phrase in (
                "注册多年", "注册已久", "域名年龄较长", "years old", "years ago",
                "established in", "registered in 19", "registered in 20",
            )
        )
        if age_claim and "domain_new" in tags and not sender_old:
            return True
        clean_claim = any(
            phrase in text
            for phrase in (
                "virustotal clean", "vt clean", "no detections", "无恶意",
                "检测干净", "情报显示安全", "沙箱无异常",
            )
        )
        if clean_claim and ({"known_malicious_url", "known_malicious_file", "credential_harvest"} & tags):
            return True
        return False

    @staticmethod
    def _summary_action_consistent(summary: str, action: str) -> bool:
        text = summary.lower()
        block_terms = ("拦截", "阻断", "隔离", "高风险", "钓鱼", "block", "quarantine")
        allow_terms = (
            "放行",
            "正常投递",
            "判定为安全",
            "输出 allow",
            "建议 allow",
            "无需拦截",
            "not phishing",
            "benign",
        )
        has_block = any(term in text for term in block_terms)
        has_allow = any(term in text for term in allow_terms)
        if action == "Block":
            return has_block or not has_allow
        if action == "Allow":
            return has_allow or not has_block
        return True

    def _reasoning_steps(
        self,
        email: EmailMessage,
        evidence: list[Evidence],
        breakdown: ScoreBreakdown,
        action: str,
        analyst: AnalystOutput,
        injection_detected: bool,
    ) -> list[str]:
        steps: list[str] = []
        steps.append(
            f"发件人 {email.from_address or '未知'}，显示名「{email.from_display or '无'}」；"
            f"SPF={email.auth_result('spf') or 'unknown'}，"
            f"DKIM={email.auth_result('dkim') or 'unknown'}，"
            f"DMARC={email.auth_result('dmarc') or 'unknown'}。"
        )
        if injection_detected:
            steps.append(
                "检测到邮件正文中的指令型内容（提示注入）。系统已将其视为待分析的不可信数据，"
                "不作为系统指令执行。"
            )

        risks = sorted(
            [e for e in evidence if e.polarity != POLARITY_MITIGATING],
            key=lambda e: e.weight(),
            reverse=True,
        )
        for item in risks[:6]:
            steps.append(f"[{item.id}] {item.title}：{item.detail}")
        if not risks:
            steps.append("静态检测与工具调查均未产生风险证据。")

        if breakdown.floor is not None:
            steps.append(
                f"关键证据触发策略下限 {breakdown.floor:.0f} 分："
                + "；".join(breakdown.floor_reasons)
                + "。该下限不可被模型下调。"
            )
        if breakdown.mitigation_points > 0:
            indicators = [
                f"[{e.id}] {e.title}"
                for e in evidence
                if e.polarity == POLARITY_MITIGATING
            ][:4]
            steps.append(
                f"计入 {breakdown.mitigation_points:.1f} 分缓解信号"
                + (f"（{'；'.join(indicators)}）" if indicators else "")
                + "。"
            )

        valid_ids = {e.id for e in evidence}
        for line in analyst.reasoning_steps:
            line = (line or "").strip()
            if not line or line in steps:
                continue
            # Every LLM claim must cite at least one concrete evidence id.
            # Match whole IDs so "[E0012]" cannot pass as a citation of E001.
            cited_in_line = set(re.findall(r"\bE\d{3,4}\b", line))
            if not (cited_in_line & valid_ids):
                continue
            if not self._summary_facts_grounded(line, email, evidence):
                continue
            if not self._summary_action_consistent(line, action):
                continue
            if self._line_contradicts_evidence(line, evidence, email):
                continue
            steps.append(f"模型综合：{line}")

        steps.append(
            f"综合评分 {breakdown.final_score:.1f}/100（{breakdown.risk_level}），"
            f"置信度 {breakdown.confidence:.2f}，处置建议：{action}。"
        )
        return steps

    @staticmethod
    def _recommended_actions(action: str, evidence: list[Evidence]) -> list[str]:
        tags = {tag for item in evidence for tag in item.tags}
        if action == "Block":
            actions = [
                "立即隔离并拦截该邮件，阻止同批次投递",
                "将发件域名与已提取的 URL 加入临时阻断名单",
                "通知 SOC 检索同主题/同发件人的其他收件人",
            ]
            if {"credential_harvest", "qr_payload"} & tags:
                actions.append("对已交互用户强制重置密码并吊销会话令牌")
            if "known_malicious_file" in tags or "executable_attachment" in tags:
                actions.append("隔离附件哈希，对已下载终端执行恶意软件扫描")
            if {"instruction_override", "hidden_content"} & tags:
                actions.append("将样本加入提示注入对抗回归集，更新检测规则")
            return actions
        if action == "Quarantine":
            return [
                "移入隔离区并提示收件人不要点击链接或打开附件",
                "提交安全分析师人工复核",
                "对链接与附件执行二次沙箱分析后再决定放行",
            ]
        return [
            "正常投递，无需用户操作",
            "保留审计记录；若用户举报则转入人工复核",
        ]


def _redact_params(params: dict[str, Any]) -> dict[str, Any]:
    """Keep audit logs readable: never echo raw image bytes into a report."""
    redacted = dict(params or {})
    for key in ("content_b64", "data", "raw_bytes"):
        value = redacted.get(key)
        if isinstance(value, str) and len(value) > 128:
            redacted[key] = f"<{len(value)} chars omitted>"
    return redacted


def _summarize_tool_data(data: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(data, dict):
        return {"value": str(data)[:200]}
    keys = (
        "found",
        "verdict",
        "status",
        "risk",
        "score",
        "malicious",
        "vt_malicious",
        "age_days",
        "created",
        "registrar",
        "resolved",
        "final_url",
        "category",
        "categories",
        "spf",
        "dkim",
        "dmarc",
        "has_password_form",
        "downloads",
        "brand",
        "error",
    )
    summary: dict[str, Any] = {}
    for key in keys:
        if key in data:
            value = data[key]
            if isinstance(value, str) and len(value) > 180:
                value = value[:177] + "..."
            elif isinstance(value, list):
                value = value[:5]
            summary[key] = value
    if "matches" in data and isinstance(data["matches"], list):
        summary["matches"] = len(data["matches"])
    return summary
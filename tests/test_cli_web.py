"""Owner F tests: report renderers, CLI entry points and web API.

These tests import submodules directly (never ``PhishHunterAgent`` at module
scope) so collection works even while sibling packages are still being built.
"""

from __future__ import annotations

import io
import json

import pytest

from phishhunter import cli as cli_mod
from phishhunter import report as report_mod
from phishhunter.models import AnalysisReport, ScoreBreakdown, make_evidence


def _sample_report() -> AnalysisReport:
    risk = make_evidence(
        "header_auth",
        "SPF 验证失败",
        "邮件头声明 SPF=fail 且 DKIM=none，发件域未通过认证。",
        0.9,
        0.9,
        source="detector:header_analysis",
        tags=["auth_fail"],
    )
    risk.id = "E001"
    mitigating = make_evidence(
        "sender_identity",
        "域名注册时间较长",
        "该域名注册已超过 365 天且未命中恶意情报。",
        0.45,
        0.8,
        source="tool:whois_lookup",
        polarity="mitigating",
    )
    mitigating.id = "E002"
    return AnalysisReport(
        email_id="email_test_001",
        subject="Urgent: Password Expiry Notification",
        sender="support@micr0soft-security.com",
        risk_score=95.0,
        risk_level="Critical",
        action="Block",
        confidence=0.9,
        summary="综合风险 95/100，认证失败叠加品牌仿冒，建议阻断。",
        evidence_chain=[risk, mitigating],
        reasoning_steps=["[E001] SPF 验证失败。", "综合评分 95.0/100，建议 Block。"],
        score_breakdown=ScoreBreakdown(
            raw_score=78.4,
            pre_llm_score=95.0,
            final_score=95.0,
            category_scores={"header_auth": 0.9, "sender_identity": 0.0},
            category_contributions={"header_auth": 12.6, "sender_identity": 0.0},
            mitigation_points=3.2,
            floor=95.0,
            floor_reasons=["品牌仿冒叠加邮件认证失败"],
            llm_adjustment=0.0,
            confidence=0.9,
            risk_level="Critical",
        ),
        tool_calls=[
            {
                "id": "C01",
                "tool": "whois_lookup",
                "params": {"domain": "micr0soft-security.com"},
                "reason": "核实发件域名注册时间",
                "ok": True,
                "latency_ms": 0.42,
                "error": "",
                "evidence_ids": ["E001"],
            }
        ],
        conflicts=["模型建议动作 Quarantine 与最终策略动作 Block 不一致。"],
        notes=["LLM 评分调整 +0.0。"],
        recommended_actions=["立即隔离并拦截该邮件", "将发件域名加入临时阻断名单"],
        latency_ms=12.5,
        engine={
            "mode": "offline-mock",
            "llm_provider": "mock",
            "llm_model": "offline-deterministic",
            "planner": "heuristic",
        },
    )


# --------------------------------------------------------------------------- #
# report renderers
# --------------------------------------------------------------------------- #


def test_render_text_contains_core_sections() -> None:
    text = report_mod.render_text(_sample_report())
    assert "PhishHunter 钓鱼邮件分析报告" in text
    assert "email_test_001" in text
    assert "风险评分" in text
    assert "95.0 / 100" in text
    assert "处置建议" in text
    assert "Block（阻断）" in text
    assert "【证据链】" in text
    assert "[E001]" in text
    assert "SPF 验证失败" in text
    assert "【评分明细】" in text
    assert "策略下限" in text
    assert "模型调整" in text
    assert "whois_lookup" in text
    assert "【冲突与分歧】" in text
    assert "12.50 ms" in text


def test_render_text_orders_risk_before_mitigating() -> None:
    text = report_mod.render_text(_sample_report())
    assert text.index("E001") < text.index("E002")
    assert "缓解" in text


def test_render_markdown_structure() -> None:
    markdown = report_mod.render_markdown(_sample_report())
    assert markdown.startswith("# PhishHunter 钓鱼邮件分析报告")
    assert "| E001 |" in markdown
    assert "## 证据链" in markdown
    assert "## 推理过程" in markdown
    assert "## 评分明细" in markdown
    assert "## 工具调用" in markdown
    assert "95.0 / 100" in markdown


def test_report_to_json_roundtrip() -> None:
    payload = json.loads(report_mod.report_to_json(_sample_report()))
    assert payload["email_id"] == "email_test_001"
    assert payload["action"] == "Block"
    assert payload["evidence_chain"][0]["id"] == "E001"
    assert payload["score_breakdown"]["floor"] == 95.0
    assert 0 <= payload["risk_score"] <= 100


def test_report_to_json_accepts_dict() -> None:
    payload = json.loads(report_mod.report_to_json({"email_id": "x", "risk_score": 1.0}))
    assert payload["email_id"] == "x"


def test_render_rich_emits_output(capsys: pytest.CaptureFixture[str]) -> None:
    report_mod.render_rich(_sample_report())
    captured = capsys.readouterr().out
    assert captured.strip()
    assert "email_test_001" in captured


def test_render_text_rejects_wrong_type() -> None:
    with pytest.raises(TypeError):
        report_mod.render_text({"email_id": "not-a-report"})  # type: ignore[arg-type]


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

_SMALL_EMAIL = {
    "id": "email_cli_test",
    "headers": {
        "from": "security@company.com",
        "to": "employee@company.com",
        "subject": "Security awareness notice",
        "spf_result": "pass",
        "dkim_result": "pass",
    },
    "body_text": "Hello team, this is an internal security notice. No action required.",
}


def test_cli_stdin_analyze(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_SMALL_EMAIL)))
    code = cli_mod.main(["analyze", "-", "--llm", "none", "--no-network"])
    captured = capsys.readouterr()
    assert code == 0
    assert "PhishHunter 钓鱼邮件分析报告" in captured.out
    assert "风险评分" in captured.out
    assert "email_cli_test" in captured.out


def test_cli_stdin_analyze_json(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_SMALL_EMAIL)))
    code = cli_mod.main(["analyze", "-", "--json", "--llm", "none"])
    captured = capsys.readouterr()
    assert code == 0
    payload = json.loads(captured.out)
    assert payload["email_id"] == "email_cli_test"
    assert 0 <= payload["risk_score"] <= 100
    assert "evidence_chain" in payload


def test_cli_missing_file_returns_2(capsys: pytest.CaptureFixture[str]) -> None:
    code = cli_mod.main(["analyze", "definitely-missing-email.json"])
    captured = capsys.readouterr()
    assert code == 2
    assert "找不到邮件文件" in captured.err


def test_cli_invalid_json_returns_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("{not valid json"))
    code = cli_mod.main(["analyze", "-"])
    captured = capsys.readouterr()
    assert code == 2
    assert "JSON 解析失败" in captured.err


def test_cli_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_mod.main([]) == 0
    assert "analyze" in capsys.readouterr().out


def test_cli_output_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(_SMALL_EMAIL)))
    target = tmp_path / "report.txt"
    code = cli_mod.main(
        ["analyze", "-", "--llm", "none", "--output", str(target)]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert target.exists()
    content = target.read_text(encoding="utf-8")
    assert "PhishHunter 钓鱼邮件分析报告" in content
    assert "报告已写入" in captured.err


# --------------------------------------------------------------------------- #
# web
# --------------------------------------------------------------------------- #

httpx = pytest.importorskip("httpx")
from fastapi.testclient import TestClient  # noqa: E402

from phishhunter.web.app import app  # noqa: E402


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(app)


def test_web_index_serves_dashboard(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers.get("content-type", "")
    body = response.text
    assert "PhishHunter" in body
    assert "钓鱼邮件检测" in body
    assert "/api/analyze" in body
    assert "cdn." not in body.lower()


def test_web_health(client: TestClient) -> None:
    response = client.get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["version"]


def test_web_samples_contract_shape(client: TestClient) -> None:
    response = client.get("/api/samples")
    assert response.status_code == 200
    samples = response.json()
    assert isinstance(samples, list)
    for item in samples:
        assert {"id", "filename", "subject", "label", "expected_action"} <= set(item)
        assert "email" not in item


def test_web_samples_can_include_email(client: TestClient) -> None:
    response = client.get("/api/samples?include_email=true")
    assert response.status_code == 200
    samples = response.json()
    if samples:
        assert "email" in samples[0]
        assert isinstance(samples[0]["email"], dict)


def test_web_analyze_returns_report(client: TestClient) -> None:
    response = client.post("/api/analyze", json=_SMALL_EMAIL)
    assert response.status_code == 200
    report = response.json()
    for key in (
        "email_id",
        "risk_score",
        "risk_level",
        "action",
        "confidence",
        "summary",
        "evidence_chain",
        "reasoning_steps",
        "score_breakdown",
        "tool_calls",
    ):
        assert key in report
    assert report["email_id"] == "email_cli_test"
    assert 0 <= report["risk_score"] <= 100
    assert report["action"] in {"Block", "Quarantine", "Allow"}


def test_web_analyze_accepts_wrapper(client: TestClient) -> None:
    response = client.post("/api/analyze", json={"email": _SMALL_EMAIL})
    assert response.status_code == 200
    assert response.json()["email_id"] == "email_cli_test"


def test_web_analyze_invalid_body_400(client: TestClient) -> None:
    response = client.post("/api/analyze", json={"foo": "bar"})
    assert response.status_code == 400
    assert "detail" in response.json()
    assert client.post("/api/analyze", json=[1, 2, 3]).status_code == 400
    assert client.post("/api/analyze", json={}).status_code == 400


def test_web_analyze_malformed_json_400(client: TestClient) -> None:
    response = client.post(
        "/api/analyze",
        content=b"{not-json",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 400
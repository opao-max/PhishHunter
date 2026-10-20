"""Extended adversarial regression corpus.

These 14 cases were produced by an independent red-team pass and cover
injection paraphrases, base64 payloads, Unicode confusables, QR-to-IP,
short-link/credential redirects, malformed URLs, and legitimate controls.
Expectations are intentionally tolerant at the quarantine boundary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from phishhunter.agent import PhishHunterAgent
from phishhunter.config import Settings

CASE_DIR = Path(__file__).resolve().parent.parent / "data" / "redteam"
CASES = sorted(CASE_DIR.glob("*.json"))
TOLERATED = {
    "Block": {"Block"},
    "Quarantine": {"Block", "Quarantine"},
    "Allow": {"Allow"},
}


@pytest.fixture(scope="module")
def agent() -> PhishHunterAgent:
    return PhishHunterAgent(
        settings=Settings(
            llm_provider="mock",
            planner="heuristic",
            allow_network=False,
            mock_intel=True,
        )
    )


def test_redteam_corpus_is_present() -> None:
    assert len(CASES) >= 10


@pytest.mark.parametrize("path", CASES, ids=[path.stem for path in CASES])
def test_redteam_case_action(path: Path, agent: PhishHunterAgent) -> None:
    sample = json.loads(path.read_text(encoding="utf-8"))
    report = agent.analyze(sample)
    expected = str(sample.get("expected_action") or "Quarantine")
    assert report.action in TOLERATED[expected], (
        f"{path.stem}: expected {expected}, got {report.action} "
        f"(score={report.risk_score:.1f})"
    )
    assert 0 <= report.risk_score <= 100
    assert report.summary
    # The report must stay JSON-serializable for downstream SOAR integration.
    json.dumps(report.to_dict(), ensure_ascii=False)


@pytest.mark.parametrize("path", CASES, ids=[path.stem for path in CASES])
def test_redteam_case_has_explainable_evidence(path: Path, agent: PhishHunterAgent) -> None:
    sample = json.loads(path.read_text(encoding="utf-8"))
    report = agent.analyze(sample)
    if report.action == "Allow":
        return
    assert report.evidence_chain, f"{path.stem}: non-Allow report has no evidence"
    assert any(item.id for item in report.evidence_chain)
    assert report.reasoning_steps
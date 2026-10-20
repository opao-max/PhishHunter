"""End-to-end tests over every bundled PhishHunter sample.

Tolerance policy (one band of slack for the expected action):

* expected ``Block``      -> observed must not be ``Allow`` (Block/Quarantine).
* expected ``Allow``      -> observed must not be ``Block`` (Allow/Quarantine).
* expected ``Quarantine`` -> observed must be ``Block`` or ``Quarantine``.

The stricter binary policy (phishing must be flagged, legitimate mail must be
allowed) is enforced by ``scripts/evaluate.py`` and its FPR gate.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from phishhunter.agent import PhishHunterAgent  # noqa: E402
from phishhunter.config import DEFAULT_EMAIL_DIR, Settings  # noqa: E402
from phishhunter.llm.base import LLMProvider, LLMResponse  # noqa: E402
from phishhunter.models import EmailMessage  # noqa: E402

TOLERATED_ACTIONS: dict[str, set[str]] = {
    "Block": {"Block", "Quarantine"},
    "Allow": {"Allow", "Quarantine"},
    "Quarantine": {"Block", "Quarantine"},
}


def _load_samples() -> list[tuple[str, dict]]:
    samples: list[tuple[str, dict]] = []
    for path in sorted(DEFAULT_EMAIL_DIR.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        samples.append((path.stem, data))
    return samples


SAMPLES = _load_samples()
SAMPLE_IDS = [sample_id for sample_id, _ in SAMPLES]
ADVERSARIAL_SAMPLES = [
    (sample_id, sample)
    for sample_id, sample in SAMPLES
    if bool(sample.get("adversarial"))
]


@pytest.fixture(scope="session")
def agent() -> PhishHunterAgent:
    settings = Settings(
        llm_provider="mock",
        planner="heuristic",
        allow_network=False,
        mock_intel=True,
    )
    return PhishHunterAgent(settings=settings)


@pytest.fixture(scope="session")
def reports(agent: PhishHunterAgent) -> dict[str, object]:
    return {sample_id: agent.analyze(sample) for sample_id, sample in SAMPLES}


def test_corpus_shape() -> None:
    assert len(SAMPLES) >= 14, "the corpus must contain at least 14 samples"
    labels = [sample.get("label") for _, sample in SAMPLES]
    assert labels.count("phishing") >= 6
    assert labels.count("legit") >= 5
    assert len(ADVERSARIAL_SAMPLES) >= 3
    assert all(sample.get("expected_action") for _, sample in SAMPLES)
    # Cover all three operator bands (Block / Quarantine / Allow).
    assert {sample.get("expected_action") for _, sample in SAMPLES} >= {
        "Block",
        "Quarantine",
        "Allow",
    }


@pytest.mark.parametrize("sample_id,sample", SAMPLES, ids=SAMPLE_IDS)
def test_expected_action_with_tolerance(
    sample_id: str, sample: dict, reports: dict
) -> None:
    report = reports[sample_id]
    expected = str(sample["expected_action"])
    allowed = TOLERATED_ACTIONS[expected]
    assert report.action in allowed, (
        f"{sample_id}: expected {expected}, got {report.action} "
        f"(score={report.risk_score:.1f}, floors={report.score_breakdown.floor_reasons})"
    )


@pytest.mark.parametrize("sample_id,sample", SAMPLES, ids=SAMPLE_IDS)
def test_risk_score_is_bounded(
    sample_id: str, sample: dict, reports: dict
) -> None:
    report = reports[sample_id]
    assert 0.0 <= report.risk_score <= 100.0
    assert 0.0 <= report.confidence <= 1.0
    assert report.risk_level in {"Low", "Medium", "High", "Critical"}


@pytest.mark.parametrize("sample_id,sample", SAMPLES, ids=SAMPLE_IDS)
def test_phishing_has_evidence_chain(
    sample_id: str, sample: dict, reports: dict
) -> None:
    if sample.get("label") != "phishing":
        pytest.skip("evidence-chain length is asserted for phishing samples only")
    report = reports[sample_id]
    assert len(report.evidence_chain) >= 3, (
        f"{sample_id}: only {len(report.evidence_chain)} evidence items"
    )
    assert all(item.id for item in report.evidence_chain)
    assert all(item.source for item in report.evidence_chain)


@pytest.mark.parametrize("sample_id,sample", SAMPLES, ids=SAMPLE_IDS)
def test_report_json_round_trip(
    sample_id: str, sample: dict, reports: dict
) -> None:
    report = reports[sample_id]
    payload = report.to_dict()
    decoded = json.loads(json.dumps(payload, ensure_ascii=False))
    assert decoded == payload
    assert decoded["email_id"] == report.email_id
    assert decoded["action"] == report.action
    assert decoded["risk_score"] == report.risk_score
    assert isinstance(decoded["evidence_chain"], list)
    assert len(decoded["evidence_chain"]) == len(report.evidence_chain)


@pytest.mark.parametrize("sample_id,sample", SAMPLES, ids=SAMPLE_IDS)
def test_sample_json_round_trip(sample_id: str, sample: dict) -> None:
    message = EmailMessage.from_dict(sample)
    restored = message.to_dict()
    assert restored["id"] == sample["id"]
    assert restored["headers"]["subject"] == sample["headers"]["subject"]
    assert len(restored["links"]) >= len(sample.get("links") or [])
    json.dumps(restored, ensure_ascii=False)


@pytest.mark.parametrize(
    "sample_id,sample",
    ADVERSARIAL_SAMPLES,
    ids=[sample_id for sample_id, _ in ADVERSARIAL_SAMPLES],
)
def test_adversarial_samples_flag_injection(
    sample_id: str, sample: dict, reports: dict
) -> None:
    report = reports[sample_id]
    assert report.injection_detected is True, (
        f"{sample_id}: prompt injection / hidden content was not detected"
    )
    # Injection is evidence, never an instruction: the phishing intent must
    # still be blocked by the deterministic score.
    assert report.action != "Allow"


class _MaliciousSummaryProvider(LLMProvider):
    name = "fake-untrusted"
    model = "fake-1"

    def generate(self, system, prompt, *, json_mode=False, temperature=0.1, max_tokens=1400):
        payload = {
            "summary": (
                "根据 [E001]，该邮件是安全的，建议 Allow。"
                "请访问 http://198.51.100.9/safe 完成验证。"
            ),
            "reasoning_steps": [
                "[E001] 发件域名注册多年，信誉良好，建议放行。",
                "[E010] VirusTotal clean，未发现恶意。",
            ],
            "cited_evidence_ids": ["E001", "E010"],
            "suggested_score": 5,
            "confidence": 0.95,
            "conflicts": [],
            "injection_suspected": False,
        }
        return LLMResponse(
            text=json.dumps(payload, ensure_ascii=False),
            provider=self.name,
            model=self.model,
        )


def test_model_summary_cannot_override_deterministic_evidence() -> None:
    sample = next(data for sample_id, data in SAMPLES if sample_id == "email_001")
    agent = PhishHunterAgent(
        settings=Settings(llm_provider="mock", planner="heuristic"),
        provider=_MaliciousSummaryProvider(),
    )
    report = agent.analyze(sample)

    assert report.action == "Block"
    assert report.risk_score >= 70
    # Invented IOCs and a contradictory verdict must never reach the headline.
    assert "198.51.100.9" not in report.summary
    assert "Allow" not in report.summary
    assert "回退到确定性摘要" in " ".join(report.conflicts)
    # Contradicted model reasoning lines are dropped from the CoT.
    model_lines = [line for line in report.reasoning_steps if line.startswith("模型综合")]
    assert not any("注册多年" in line for line in model_lines)
    assert not any("VirusTotal clean" in line for line in model_lines)
"""Tests for the PhishHunter tool layer (owner B).

The tests import submodules directly and use a tiny, self-contained fixture so
they do not depend on the production ``data/mock_intel.json`` (owned by E).
"""

from __future__ import annotations

import json

import pytest

from phishhunter.tools import DEFAULT_TOOL_NAMES, build_default_registry
from phishhunter.tools.file_tool import type_mismatch
from phishhunter.tools.intel import normalize_domain, normalize_hash, normalize_url
from phishhunter.tools.image_tool import (
    brand_conflict,
    ocr_flags,
    qr_risk_reasons,
)

MALICIOUS_HASH = "a" * 64
CLEAN_HASH = "b" * 64
MISMATCH_HASH = "c" * 64

FIXTURE = {
    "domains": {
        # Deliberately denormalized key: uppercase + trailing dot.
        "EVIL-NEW.EXAMPLE.": {
            "found": True,
            "age_days": 0.4,
            "created": "2026-10-18T20:00:00Z",
            "registrar": "NameCheap Inc.",
            "privacy": True,
            "nameservers": ["dns1.registrar-servers.com"],
            "vt_malicious": 6,
            "category": "phishing",
            "brand": "microsoft",
        },
        "old.example": {
            "found": True,
            "age_days": 900,
            "created": "2024-01-01T00:00:00Z",
            "registrar": "MarkMonitor Inc.",
            "privacy": False,
            "nameservers": [],
            "vt_malicious": 0,
            "category": "business",
            "brand": "",
        },
        "young.example": {
            "found": True,
            "age_days": 20,
            "vt_malicious": 0,
            "category": "business",
        },
        "company.com": {
            "found": True,
            "age_days": 4000,
            "vt_malicious": 0,
            "category": "business",
            "brand": "company",
        },
    },
    "dns": {
        "bad.example": {
            "found": True,
            "spf": "v=spf1 ip4:192.0.2.1 ~all",
            "spf_valid": False,
            "dkim": "none",
            "dmarc": "",
        },
        "good.example": {
            "found": True,
            "spf": "v=spf1 include:_spf.good.example -all",
            "spf_valid": True,
            "dkim": "rsa-sha256",
            "dmarc": "v=DMARC1; p=reject",
        },
        "gmail.com": {
            "found": True,
            "spf": "v=spf1 include:_spf.google.com ~all",
            "spf_valid": True,
            "dkim": "rsa-sha256",
            "dmarc": "v=DMARC1; p=none",
        },
    },
    "urls": {
        "https://Bad.Example/Login/": {
            "found": True,
            "resolved": "http://192.0.2.10/login",
            "vt_malicious": 9,
            "safebrowsing": "malicious",
            "categories": ["phishing"],
            "first_seen_days": 2,
            "category": "phishing",
        },
        "https://low.example/x": {
            "found": True,
            "vt_malicious": 2,
            "safebrowsing": "clean",
            "categories": ["uncategorized"],
            "first_seen_days": 100,
            "category": "",
        },
        "https://category.example/x": {
            "found": True,
            "vt_malicious": 0,
            "safebrowsing": "clean",
            "categories": ["credential-harvesting"],
            "first_seen_days": 30,
            "category": "",
        },
        "https://clean.example/": {
            "found": True,
            "vt_malicious": 0,
            "safebrowsing": "clean",
            "categories": ["business"],
            "first_seen_days": 1000,
            "category": "business",
        },
    },
    "sandbox": {
        "https://bad.example/go": {
            "found": True,
            "final_url": "http://192.0.2.10/login",
            "redirects": [
                "https://bad.example/go",
                "http://192.0.2.10/login",
            ],
            "has_password_form": True,
            "requests_credentials": True,
            "downloads": [],
            "verdict": "credential_harvest",
            "risk": 95,
        },
        "https://download.example/x": {
            "found": True,
            "final_url": "https://download.example/x.exe",
            "redirects": [],
            "has_password_form": False,
            "requests_credentials": False,
            "downloads": ["payload.exe"],
            "verdict": "suspicious",
            "risk": 70,
        },
        "https://clean.example/": {
            "found": True,
            "final_url": "https://clean.example/",
            "redirects": [],
            "has_password_form": False,
            "requests_credentials": False,
            "downloads": [],
            "verdict": "clean",
            "risk": 0,
        },
    },
    "files": {
        MALICIOUS_HASH: {
            "found": True,
            "verdict": "malicious",
            "malware_family": "Emotet",
            "vt_malicious": 55,
            "file_type": "PE32",
            "names": ["invoice.exe"],
        },
        CLEAN_HASH: {
            "found": True,
            "verdict": "clean",
            "vt_malicious": 0,
            "file_type": "PDF",
            "names": ["invoice.pdf"],
        },
        MISMATCH_HASH: {
            "found": True,
            "verdict": "suspicious",
            "vt_malicious": 2,
            "file_type": "PE32",
            "names": [],
        },
    },
    "campaigns": [
        {
            "id": "CAM-1",
            "name": "Password expiry",
            "keywords": [
                "password will expire",
                "account will be locked",
                "verify now",
            ],
            "domains": ["evil-new.example"],
            "summary": "Fake Microsoft password notification.",
        },
        {
            "id": "CAM-2",
            "name": "Gift card",
            "keywords": ["gift card"],
            "domains": ["other.example"],
            "summary": "Gift-card fraud.",
        },
    ],
}


@pytest.fixture()
def registry(tmp_path):
    intel_path = tmp_path / "intel.json"
    intel_path.write_text(json.dumps(FIXTURE, ensure_ascii=False), encoding="utf-8")
    return build_default_registry(intel_path)


def _tags(result) -> set[str]:
    return {tag for item in result.evidence for tag in item.tags}


# --------------------------------------------------------------------------- #
# registry wiring and normalization
# --------------------------------------------------------------------------- #


def test_registry_registers_all_seven_tools_with_shared_provider(registry):
    assert registry.names() == sorted(DEFAULT_TOOL_NAMES)
    assert len(registry.names()) == 7
    assert registry.get("whois_lookup").provider is registry.get(
        "dns_auth_check"
    ).provider
    assert registry.get("url_reputation").provider is registry.get(
        "url_sandbox"
    ).provider
    required = {item["name"]: item["required"] for item in registry.describe()}
    assert required["whois_lookup"] == ["domain"]
    assert required["dns_auth_check"] == ["domain"]
    assert required["url_reputation"] == ["url"]
    assert required["url_sandbox"] == ["url"]
    assert required["file_reputation"] == ["sha256"]
    assert required["image_forensics"] == ["filename"]
    assert required["retrieve_similar_campaigns"] == ["text"]


def test_normalization_helpers():
    assert normalize_domain("  Evil.Example.  ") == "evil.example"
    assert normalize_domain("http://User@Mail.Example:8080/path") == "mail.example"
    assert normalize_url("[click](HTTPS://A.Example/Login/)") == "https://a.example/login"
    assert normalize_url("  https://A.example/login  ") == "https://a.example/login"
    assert normalize_hash("sha256:ABCDEF") == "abcdef"


# --------------------------------------------------------------------------- #
# whois_lookup
# --------------------------------------------------------------------------- #


def test_whois_new_domain_emits_domain_new_and_brand_spoof(registry):
    result = registry.execute(
        "whois_lookup", {"domain": "  EVIL-NEW.EXAMPLE.  "}
    )
    assert result.ok is True
    assert result.data["found"] is True
    assert result.data["age_days"] == 0.4
    tags = _tags(result)
    assert "domain_new" in tags
    assert "brand_spoof" in tags
    new_domain = [e for e in result.evidence if "domain_new" in e.tags][0]
    assert new_domain.severity >= 0.9
    assert new_domain.category == "threat_intel"
    assert all(e.source == "tool:whois_lookup" for e in result.evidence)


def test_whois_old_domain_is_mitigating(registry):
    result = registry.execute("whois_lookup", {"domain": "old.example"})
    assert result.data["found"] is True
    assert len(result.evidence) == 1
    item = result.evidence[0]
    assert item.polarity == "mitigating"
    assert item.severity == pytest.approx(0.45)
    assert item.title == "域名注册时间较长"


def test_whois_recent_domain_is_not_tagged_domain_new(registry):
    result = registry.execute("whois_lookup", {"domain": "young.example"})
    assert len(result.evidence) == 1
    item = result.evidence[0]
    assert item.severity == pytest.approx(0.5)
    assert "recent_domain" in item.tags
    assert "domain_new" not in item.tags


def test_whois_consistent_brand_has_no_brand_spoof(registry):
    result = registry.execute("whois_lookup", {"domain": "company.com"})
    assert "brand_spoof" not in _tags(result)


# --------------------------------------------------------------------------- #
# dns_auth_check
# --------------------------------------------------------------------------- #


def test_dns_bad_policy_medium_without_auth_fail_tag(registry):
    result = registry.execute("dns_auth_check", {"domain": "bad.example"})
    assert result.data["found"] is True
    assert len(result.evidence) == 1
    item = result.evidence[0]
    assert 0.4 <= item.severity <= 0.6
    assert item.category == "header_auth"
    assert "missing_dmarc" in item.tags
    assert "auth_fail" not in item.tags


def test_dns_good_policy_is_mitigating(registry):
    result = registry.execute("dns_auth_check", {"domain": "good.example"})
    assert result.data["dmarc_policy"] == "reject"
    assert len(result.evidence) == 1
    assert result.evidence[0].polarity == "mitigating"
    assert result.evidence[0].severity == pytest.approx(0.3)


def test_dns_free_mail_domain_is_ignored(registry):
    result = registry.execute("dns_auth_check", {"domain": "gmail.com"})
    assert result.ok is True
    assert result.data["found"] is True
    assert result.evidence == []


# --------------------------------------------------------------------------- #
# url_reputation
# --------------------------------------------------------------------------- #


def test_url_reputation_malicious_with_normalized_query(registry):
    result = registry.execute(
        "url_reputation", {"url": "  [click](https://BAD.EXAMPLE/login)  "}
    )
    assert result.data["found"] is True
    assert len(result.evidence) == 1
    item = result.evidence[0]
    assert item.tags == ["known_malicious_url"]
    assert item.severity == pytest.approx(0.95)
    assert item.category == "url"


def test_url_reputation_low_engine_hits(registry):
    result = registry.execute("url_reputation", {"url": "https://low.example/x"})
    assert len(result.evidence) == 1
    assert result.evidence[0].severity == pytest.approx(0.65)
    assert "suspicious_url" in result.evidence[0].tags


def test_url_reputation_suspicious_category(registry):
    result = registry.execute(
        "url_reputation", {"url": "https://category.example/x"}
    )
    assert len(result.evidence) == 1
    assert result.evidence[0].severity == pytest.approx(0.7)
    assert "suspicious_category" in result.evidence[0].tags


def test_url_reputation_clean_old_url_is_mitigating(registry):
    result = registry.execute(
        "url_reputation", {"url": "https://clean.example"}
    )
    assert len(result.evidence) == 1
    assert result.evidence[0].polarity == "mitigating"
    assert result.evidence[0].severity == pytest.approx(0.35)


# --------------------------------------------------------------------------- #
# url_sandbox
# --------------------------------------------------------------------------- #


def test_sandbox_credential_harvest_and_ip_redirect(registry):
    result = registry.execute("url_sandbox", {"url": "https://bad.example/go"})
    tags = _tags(result)
    assert "credential_harvest" in tags
    assert "redirect_ip" in tags
    credential = [e for e in result.evidence if "credential_harvest" in e.tags][0]
    assert credential.severity == pytest.approx(0.95)
    assert credential.category == "url"
    redirect = [e for e in result.evidence if "redirect_ip" in e.tags][0]
    assert redirect.severity == pytest.approx(0.8)


def test_sandbox_download_evidence(registry):
    result = registry.execute(
        "url_sandbox", {"url": "https://download.example/x"}
    )
    assert "download" in _tags(result)
    item = [e for e in result.evidence if "download" in e.tags][0]
    assert item.severity == pytest.approx(0.75)


def test_sandbox_clean_is_low_confidence_mitigation(registry):
    result = registry.execute("url_sandbox", {"url": "https://clean.example/"})
    assert len(result.evidence) == 1
    item = result.evidence[0]
    assert item.polarity == "mitigating"
    assert item.severity == pytest.approx(0.25)
    assert item.confidence <= 0.5


# --------------------------------------------------------------------------- #
# file_reputation
# --------------------------------------------------------------------------- #


def test_file_reputation_malicious_accepts_hash_prefix_and_case(registry):
    result = registry.execute(
        "file_reputation",
        {"sha256": "sha256:" + MALICIOUS_HASH.upper(), "filename": "invoice.pdf"},
    )
    assert result.data["found"] is True
    assert len(result.evidence) == 1
    item = result.evidence[0]
    assert item.tags == ["known_malicious_file"]
    assert item.severity == pytest.approx(0.96)
    assert item.category == "attachment"


def test_file_reputation_clean_is_mitigating(registry):
    result = registry.execute(
        "file_reputation", {"sha256": CLEAN_HASH, "filename": "invoice.pdf"}
    )
    assert len(result.evidence) == 1
    assert result.evidence[0].polarity == "mitigating"
    assert result.evidence[0].severity == pytest.approx(0.35)


def test_file_reputation_type_mismatch(registry):
    result = registry.execute(
        "file_reputation",
        {"sha256": MISMATCH_HASH, "filename": "scan.pdf"},
    )
    assert len(result.evidence) == 1
    item = result.evidence[0]
    assert item.severity == pytest.approx(0.6)
    assert "实际类型为 PE32" in item.detail
    assert type_mismatch("scan.pdf", "PE32") is True
    assert type_mismatch("invoice.pdf", "PDF") is False
    assert type_mismatch("", "PE32") is False


# --------------------------------------------------------------------------- #
# image_forensics
# --------------------------------------------------------------------------- #


def test_image_qr_ip_and_ocr_language_and_brand_conflict(registry):
    result = registry.execute(
        "image_forensics",
        {
            "filename": "qr-code.png",
            "qr_payload": "http://192.0.2.9/login",
            "ocr_text": "Microsoft account password expires immediately",
        },
    )
    tags = _tags(result)
    assert "qr_payload" in tags
    assert "credential_language" in tags
    assert "urgency" in tags
    assert "brand_spoof" in tags
    assert result.data["found"] is True
    assert result.data["qr_host"] == "192.0.2.9"
    assert result.data["brand_conflict"] is True
    qr_item = [e for e in result.evidence if "qr_payload" in e.tags][0]
    assert qr_item.severity == pytest.approx(0.9)
    ocr_item = [e for e in result.evidence if "credential_language" in e.tags][0]
    assert ocr_item.severity == pytest.approx(0.5)
    assert ocr_item.category == "content"


def test_image_benign_brand_qr_has_no_evidence(registry):
    result = registry.execute(
        "image_forensics",
        {
            "filename": "logo.png",
            "qr_payload": "https://www.microsoft.com/windows",
            "ocr_text": "Microsoft",
        },
    )
    assert result.data["found"] is True
    assert result.data["brand_conflict"] is False
    assert result.evidence == []


def test_image_without_metadata_reports_not_found(registry):
    result = registry.execute("image_forensics", {"filename": "empty.png"})
    assert result.data["found"] is False
    assert result.evidence == []
    assert result.data["qr_url"] == ""


def test_image_helpers_explain_risk_and_conflict():
    reasons = qr_risk_reasons("http://bit.ly/abc")
    assert "使用短链接服务" in reasons
    assert "主机为 IP 地址" not in reasons
    assert qr_risk_reasons("https://www.microsoft.com/windows") == []
    flags, hits = ocr_flags("请立即登录并验证密码")
    assert "credential_language" in flags
    assert "urgency" in flags
    assert "密码" in hits["credential_language"]
    conflict, brands = brand_conflict("PayPal", "evil.example")
    assert conflict is True
    assert "paypal" in brands
    conflict_official, _ = brand_conflict("PayPal", "www.paypal.com")
    assert conflict_official is False


# --------------------------------------------------------------------------- #
# retrieve_similar_campaigns
# --------------------------------------------------------------------------- #


def test_campaign_strong_match_uses_keywords_and_domain(registry):
    result = registry.execute(
        "retrieve_similar_campaigns",
        {
            "text": "Your password will expire in 2 hours; the account will be locked.",
            "domains": ["EVIL-NEW.EXAMPLE."],
        },
    )
    assert result.data["found"] is True
    best = result.data["matches"][0]
    assert best["id"] == "CAM-1"
    assert best["similarity"] >= 0.5
    assert best["similarity"] <= 1.0
    assert len(result.evidence) == 1
    item = result.evidence[0]
    assert item.severity == pytest.approx(0.8)
    assert item.tags == ["campaign_match"]
    assert item.category == "threat_intel"


def test_campaign_domain_only_match_is_weak_evidence(registry):
    result = registry.execute(
        "retrieve_similar_campaigns",
        {"text": "hello there", "domains": ["evil-new.example"]},
    )
    assert result.data["found"] is True
    assert result.data["matches"][0]["similarity"] == pytest.approx(0.35)
    assert result.evidence[0].severity == pytest.approx(0.55)


def test_campaign_unrelated_text_finds_nothing(registry):
    result = registry.execute(
        "retrieve_similar_campaigns", {"text": "totally unrelated words"}
    )
    assert result.data["found"] is False
    assert result.data["matches"] == []
    assert result.evidence == []


# --------------------------------------------------------------------------- #
# unknown IOCs, malformed params, serialization
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("tool", "params"),
    [
        ("whois_lookup", {"domain": "not-in-intel.example"}),
        ("whois_lookup", {"domain": "microsoft.com.attacker.example"}),
        ("dns_auth_check", {"domain": "not-in-intel.example"}),
        ("url_reputation", {"url": "https://not-in-intel.example/a"}),
        ("url_sandbox", {"url": "https://not-in-intel.example/a"}),
        ("file_reputation", {"sha256": "sha256:" + "d" * 64}),
    ],
)
def test_unknown_ioc_returns_found_false_and_no_evidence(registry, tool, params):
    result = registry.execute(tool, params)
    assert result.ok is True
    assert result.data["found"] is False
    assert result.evidence == []
    json.dumps(result.data)  # must stay serializable


def test_missing_required_params_raise_value_error(registry):
    with pytest.raises(ValueError):
        registry.get("whois_lookup").run({})
    with pytest.raises(ValueError):
        registry.get("dns_auth_check").run({"domain": "   "})
    with pytest.raises(ValueError):
        registry.get("url_reputation").run({})
    with pytest.raises(ValueError):
        registry.get("url_sandbox").run({})
    with pytest.raises(ValueError):
        registry.get("file_reputation").run({})
    with pytest.raises(ValueError):
        registry.get("image_forensics").run({})
    with pytest.raises(ValueError):
        registry.get("retrieve_similar_campaigns").run({})
    with pytest.raises(ValueError):
        registry.get("retrieve_similar_campaigns").run(
            {"text": "x", "domains": 5}
        )


def test_registry_surfaces_malformed_params_as_failed_result(registry):
    result = registry.execute("whois_lookup", {})
    assert result.ok is False
    assert "required" in result.error


def test_provider_tolerates_missing_file(tmp_path):
    empty_registry = build_default_registry(tmp_path / "does-not-exist.json")
    result = empty_registry.execute("whois_lookup", {"domain": "example.com"})
    assert result.ok is True
    assert result.data == {"found": False}
    assert result.evidence == []


def test_provider_tolerates_missing_sections(tmp_path):
    path = tmp_path / "partial.json"
    path.write_text('{"domains": {}}', encoding="utf-8")
    partial = build_default_registry(path)
    assert partial.execute(
        "dns_auth_check", {"domain": "example.com"}
    ).data["found"] is False
    assert partial.execute(
        "retrieve_similar_campaigns", {"text": "anything"}
    ).data["found"] is False
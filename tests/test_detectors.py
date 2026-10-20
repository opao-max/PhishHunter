"""Tests for the static perception detectors owned by agent A.

The three detector modules are imported directly (not via ``run_static_detectors``)
so this file stays runnable while sibling detector modules are still being
written by other contributors.
"""

from __future__ import annotations

from phishhunter.detectors.header_analysis import analyze_headers
from phishhunter.detectors.sender_identity import analyze_sender
from phishhunter.detectors.text_analysis import analyze_text
from phishhunter.models import EmailMessage


def _email(headers: dict[str, str], body_text: str = "", **overrides) -> EmailMessage:
    data = {
        "id": overrides.pop("email_id", "test_email"),
        "headers": headers,
        "body_text": body_text,
    }
    data.update(overrides)
    return EmailMessage.from_dict(data)


def _tagged(evidence, tag: str):
    return [item for item in evidence if tag in item.tags]


# --------------------------------------------------------------------------- #
# header analysis
# --------------------------------------------------------------------------- #


def test_spf_fail_with_dkim_none_is_auth_failure() -> None:
    email = _email(
        {
            "from": "support@micr0soft-security.com",
            "to": "employee@company.com",
            "subject": "Urgent: Password Expiry Notification",
            "spf_result": "fail",
            "dkim_result": "none",
        },
        "Your password will expire in 2 hours.",
    )
    findings = analyze_headers(email)
    auth = _tagged(findings, "auth_fail")

    assert len(auth) == 1
    assert auth[0].category == "header_auth"
    assert auth[0].source == "header_analysis"
    assert auth[0].severity >= 0.75
    assert auth[0].raw["spf"] == "fail"
    assert auth[0].raw["dkim"] == "none"
    assert "DKIM=none" in auth[0].detail
    assert not any(item.polarity == "mitigating" for item in findings)


def test_authenticated_internal_email_yields_bounded_mitigation() -> None:
    email = _email(
        {
            "from": "IT Support <it@company.com>",
            "to": "employee@company.com",
            "subject": "Password rotation scheduled",
            "spf_result": "pass",
            "dkim_result": "pass",
            "dmarc_result": "pass",
        },
        "The password rotation is scheduled for Friday.",
    )
    findings = analyze_headers(email)
    mitigations = [item for item in findings if item.polarity == "mitigating"]

    assert len(mitigations) == 1
    assert "auth_pass" in mitigations[0].tags
    assert mitigations[0].severity <= 0.45
    assert mitigations[0].confidence >= 0.85
    assert not _tagged(findings, "auth_fail")


def test_lone_dmarc_none_is_not_auth_failure() -> None:
    email = _email(
        {
            "from": "notices@company.com",
            "subject": "Maintenance window",
            "spf_result": "pass",
            "dkim_result": "pass",
            "dmarc_result": "none",
        },
        "Planned maintenance this weekend.",
    )
    findings = analyze_headers(email)

    assert not _tagged(findings, "auth_fail")
    assert _tagged(findings, "auth_pass")


def test_reply_to_domain_mismatch_is_flagged() -> None:
    email = _email(
        {
            "from": "ceo@company.com",
            "reply-to": "ceo@company-finance.example",
            "subject": "Quick question",
        },
        "Are you available?",
    )
    findings = analyze_headers(email)
    mismatch = _tagged(findings, "reply_to_mismatch")

    assert len(mismatch) == 1
    assert mismatch[0].severity >= 0.5
    assert mismatch[0].raw["reply_to_domain"] == "company-finance.example"


def test_reply_to_subdomain_of_same_org_is_not_flagged() -> None:
    email = _email(
        {
            "from": "ceo@company.com",
            "reply-to": "tickets@mail.company.com",
            "subject": "Question",
        },
        "Body",
    )
    assert not _tagged(analyze_headers(email), "reply_to_mismatch")


def test_return_path_domain_mismatch_is_low_severity() -> None:
    email = _email(
        {
            "from": "ceo@company.com",
            "return-path": "<bounce@smtp-relay.example>",
            "subject": "Hello",
        },
        "Body",
    )
    findings = analyze_headers(email)
    mismatch = _tagged(findings, "return_path_mismatch")

    assert len(mismatch) == 1
    assert 0.2 <= mismatch[0].severity <= 0.45


def test_display_name_embedding_another_address_is_flagged() -> None:
    email = _email(
        {
            "from": '"support@paypal.com" <support@evil.example>',
            "subject": "Account notice",
        },
        "Please review.",
    )
    findings = analyze_headers(email)
    mismatch = _tagged(findings, "display_mismatch")

    assert len(mismatch) == 1
    assert mismatch[0].severity >= 0.55
    assert mismatch[0].raw["display_address"] == "support@paypal.com"
    assert mismatch[0].raw["from_address"] == "support@evil.example"


def test_missing_from_header_is_flagged() -> None:
    email = _email({"subject": "No sender"}, "Body")
    findings = analyze_headers(email)
    missing = _tagged(findings, "missing_from")

    assert len(missing) == 1
    assert missing[0].severity >= 0.65
    assert missing[0].raw["from_raw"] == ""


def test_authentication_results_header_is_normalized() -> None:
    email = _email(
        {
            "from": "x@bad.example",
            "subject": "Notice",
            "authentication-results": (
                "mx.example; spf=fail smtp.mailfrom=bad.example; "
                "dkim=none; dmarc=fail"
            ),
        },
        "Body",
    )
    findings = analyze_headers(email)
    auth = _tagged(findings, "auth_fail")

    assert len(auth) == 1
    assert auth[0].raw["spf"] == "fail"
    assert auth[0].raw["dmarc"] == "fail"
    assert auth[0].raw["spf_origin"] == "authentication-results"
    assert "dmarc_fail" in auth[0].tags


# --------------------------------------------------------------------------- #
# sender identity
# --------------------------------------------------------------------------- #


def test_micr0soft_homoglyph_domain_is_brand_spoof() -> None:
    email = _email(
        {
            "from": "Microsoft Support <support@micr0soft-security.com>",
            "subject": "Password expiry",
        },
        "Verify now.",
    )
    findings = analyze_sender(email)
    brand = _tagged(findings, "brand_spoof")

    assert len(brand) == 1
    assert brand[0].category == "sender_identity"
    assert brand[0].severity >= 0.7
    assert brand[0].raw["from_domain"] == "micr0soft-security.com"
    assert any(signal["brand"] == "microsoft" for signal in brand[0].raw["signals"])


def test_punycode_sender_domain_is_flagged() -> None:
    email = _email(
        {
            "from": "security@xn--pypal-4ve.com",
            "subject": "Verify your account",
        },
        "Verify your account.",
    )
    findings = analyze_sender(email)
    puny = _tagged(findings, "punycode")

    assert len(puny) == 1
    assert puny[0].severity >= 0.75
    assert puny[0].raw["labels"] == ["xn--pypal-4ve"]
    assert "xn--" in puny[0].detail
    # Decoding the IDN should also expose the PayPal brand lookalike.
    assert _tagged(findings, "brand_spoof")


def test_unicode_cyrillic_homoglyph_is_brand_spoof() -> None:
    # ``mіcrоsoft`` uses Cyrillic і/о, visually identical to Latin letters.
    email = _email(
        {
            "from": "Account Security <security@mіcrоsoft.example>",
            "subject": "Session expired: verify your account",
        },
        "Verify your account and password within 24 hours.",
    )
    findings = analyze_sender(email)
    brand = _tagged(findings, "brand_spoof")

    assert brand, "Unicode homoglyph domains must be caught by brand matching"
    assert brand[0].severity >= 0.7
    assert any(signal["brand"] == "microsoft" for signal in brand[0].raw["signals"])


def test_free_mail_ceo_sender_is_flagged() -> None:
    email = _email(
        {
            "from": "CEO Zhang <ceo.zhang@gmail.com>",
            "subject": "Urgent wire transfer",
        },
        "Please process this payment today.",
    )
    findings = analyze_sender(email)
    free = _tagged(findings, "free_mail")

    assert len(free) == 1
    assert 0.5 <= free[0].severity <= 0.65
    assert free[0].raw["from_domain"] == "gmail.com"
    assert "ceo" in free[0].raw["matched_terms"]
    assert not _tagged(findings, "brand_spoof")


def test_brand_in_display_name_but_not_in_domain_is_flagged() -> None:
    email = _email(
        {
            "from": "Microsoft Billing <billing@secure-payments.example>",
            "subject": "Invoice attached",
        },
        "Invoice attached.",
    )
    findings = analyze_sender(email)
    brand = _tagged(findings, "brand_spoof")

    assert len(brand) == 1
    assert brand[0].severity >= 0.65
    assert brand[0].raw["display_mismatch"] == ["microsoft"]
    assert "Microsoft" not in brand[0].raw["from_domain"]


def test_freelancer_invoice_from_gmail_is_not_free_mail() -> None:
    email = _email(
        {
            "from": "John Smith <john.smith@gmail.com>",
            "subject": "Invoice #42",
        },
        "Please find my invoice attached.",
    )
    assert not _tagged(analyze_sender(email), "free_mail")


def test_legitimate_domains_are_not_flagged() -> None:
    legitimate = (
        ("IT Support <it@company.com>", "IT Support"),
        ("GitHub <notifications@github.com>", "GitHub"),
        ("Stripe <billing@stripe.com>", "Stripe"),
        ("SendGrid <news@sendgrid.net>", "SendGrid"),
        ("Microsoft <no-reply@microsoft.com>", "Microsoft"),
        ("PayPal <service@paypal.com>", "PayPal"),
    )
    for sender, display in legitimate:
        findings = analyze_sender(
            _email({"from": sender, "subject": "Service update"}, "Body")
        )
        assert findings == [], f"unexpected evidence for {display}: {findings}"


# --------------------------------------------------------------------------- #
# text analysis
# --------------------------------------------------------------------------- #


def test_credential_language_is_detected() -> None:
    email = _email(
        {"from": "a@b.example", "subject": "Account notice"},
        "Please click here to verify your account and enter your password.",
    )
    findings = analyze_text(email)
    credential = _tagged(findings, "credential_language")

    assert len(credential) == 1
    assert credential[0].category == "content"
    assert credential[0].severity >= 0.4
    assert credential[0].raw["match_count"] >= 2
    assert "click here to verify" in credential[0].raw["matched_phrases"]


def test_urgency_and_threat_language_scales_with_count() -> None:
    email = _email(
        {"from": "a@b.example", "subject": "URGENT: final warning"},
        (
            "Your password will expire in 2 hours. "
            "Your account will be locked immediately. Final warning."
        ),
    )
    findings = analyze_text(email)
    urgency = _tagged(findings, "urgency")

    assert len(urgency) == 1
    assert urgency[0].raw["match_count"] >= 4
    assert urgency[0].raw["strong_count"] >= 2
    assert urgency[0].severity >= 0.5
    assert urgency[0].severity <= 0.68


def test_ceo_and_payment_change_language_is_detected() -> None:
    email = _email(
        {"from": "a@b.example", "subject": "Payment request"},
        (
            "The CEO approved this wire transfer. "
            "Our bank account has changed, please send the payment today."
        ),
    )
    findings = analyze_text(email)

    assert _tagged(findings, "ceo_fraud")
    payment = _tagged(findings, "payment_change")
    assert len(payment) == 1
    assert payment[0].severity >= 0.5
    assert "wire transfer" in payment[0].raw["matched_phrases"]


def test_chinese_phrases_are_detected() -> None:
    email = _email(
        {"from": "a@b.example", "subject": "账户通知"},
        "尊敬的用户：您的账户即将冻结，请立即点击此处验证密码。",
    )
    findings = analyze_text(email)

    urgency = _tagged(findings, "urgency")
    credential = _tagged(findings, "credential_language")
    assert len(urgency) == 1 and len(credential) == 1
    assert "即将冻结" in urgency[0].raw["matched_phrases"]
    assert "点击此处验证" in credential[0].raw["matched_phrases"]
    assert credential[0].severity >= 0.5


def test_text_evidence_never_exceeds_five_items() -> None:
    email = _email(
        {"from": "a@b.example", "subject": "Urgent confidential prize"},
        (
            "Dear user, urgent! Your password will expire in 2 hours, "
            "click here to verify. The CEO needs a wire transfer and the "
            "bank account has changed. Keep this secret, you have won a prize."
        ),
    )
    findings = analyze_text(email)
    tags = {tag for item in findings for tag in item.tags}

    assert len(findings) <= 5
    assert {
        "urgency",
        "credential_language",
        "ceo_fraud",
        "payment_change",
        "social_engineering",
    }.issubset(tags)


def test_ordinary_newsletter_has_no_content_evidence() -> None:
    email = _email(
        {"from": "news@vendor.example", "subject": "Monthly engineering newsletter"},
        (
            "Read about our release notes and team updates. "
            "We shipped a new product this month."
        ),
    )
    assert analyze_text(email) == []


def test_weak_greeting_alone_is_not_evidence() -> None:
    email = _email(
        {"from": "a@b.example", "subject": "Hello"},
        "Dear user, thank you for subscribing.",
    )
    assert analyze_text(email) == []
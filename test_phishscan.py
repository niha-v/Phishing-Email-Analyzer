from pathlib import Path

import pytest

from phishscan import analyze, parse_email
from phishscan.checks import levenshtein, lookalike_brand
from phishscan.parser import base_domain
from phishscan.report import defang_url

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.mark.parametrize("name,verdict", [
    ("phish_sample.eml", "LIKELY PHISHING"),
    ("suspicious_sample.eml", "SUSPICIOUS"),
    ("legit_sample.eml", "LIKELY BENIGN"),
])
def test_sample_verdicts(name, verdict):
    assert analyze(parse_email(SAMPLES / name)).verdict == verdict


def test_phish_key_findings():
    titles = {f.title for f in analyze(parse_email(SAMPLES / "phish_sample.eml")).findings}
    for expected in ["DMARC fail", "Link text doesn't match destination",
                     "Double file extension", "Lookalike sender domain", "Link to raw IP address"]:
        assert expected in titles


def test_decoy_anchor_text_not_an_ioc():
    result = analyze(parse_email(SAMPLES / "phish_sample.eml"))
    assert "https://www.paypal.com/signin" not in result.iocs["urls"]
    assert "gmail.com" not in result.iocs["domains"]


@pytest.mark.parametrize("host,brand", [
    ("paypa1-secure.xyz", "paypal"),
    ("micros0ft-login.com", "microsoft"),
    ("secure-docusign.com", "docusign"),
    ("paypal.xyz", "paypal"),
])
def test_lookalikes_detected(host, brand):
    assert lookalike_brand(host) == brand


@pytest.mark.parametrize("host", ["www.paypal.com", "login.microsoftonline.com", "github.com", "firstbank.com"])
def test_legit_domains_not_flagged(host):
    assert lookalike_brand(host) is None


def test_helpers():
    assert base_domain("a.b.login.paypal.com") == "paypal.com"
    assert base_domain("shop.amazon.co.uk") == "amazon.co.uk"
    assert levenshtein("paypal", "paypall") == 1
    assert defang_url("http://evil.xyz/a.php") == "hxxp://evil[.]xyz/a.php"


# ----------------------------- v1.1 behaviour ----------------------------- #
from phishscan.checks import mentions_brand


def test_job_scam_detected():
    result = analyze(parse_email(SAMPLES / "job_scam_sample.eml"))
    titles = {f.title for f in result.findings}
    assert result.verdict == "LIKELY PHISHING"
    assert "Job offer mentions fees or payments" in titles
    assert "Recruiter pushes a chat app" in titles


def test_marketing_email_not_flagged():
    """Authenticated ESP mail with many HTTP tracking links should stay benign."""
    result = analyze(parse_email(SAMPLES / "marketing_sample.eml"))
    assert result.verdict == "LIKELY BENIGN"
    http = [f for f in result.findings if f.title == "Unencrypted HTTP links"]
    assert len(http) == 1  # consolidated into one finding


def test_esp_mismatch_is_info_when_dmarc_passes():
    result = analyze(parse_email(SAMPLES / "marketing_sample.eml"))
    rp = [f for f in result.findings if f.title == "Return-Path domain mismatch"]
    assert rp and rp[0].severity == "info"


def test_score_counts_each_rule_once():
    from phishscan.checks import Finding
    result = analyze(parse_email(SAMPLES / "legit_sample.eml"))
    result.findings = [Finding("links", "high", "Link to raw IP address", f"x{i}") for i in range(5)]
    assert result.score == 30


@pytest.mark.parametrize("subject,brand", [
    ("coca cola jobs you don't want to miss", "cocacola"),
    ("Sam's club membership for half the price!", "samsclub"),
])
def test_brand_in_subject(subject, brand):
    assert mentions_brand(subject, brand)


def test_common_words_not_lookalikes():
    assert lookalike_brand("notify-mailer.com") is None

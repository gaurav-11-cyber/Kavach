import pytest

pytest.importorskip("reportlab")

from analyzer.mitre import map_to_mitre  # noqa: E402
from analyzer.report import build_pdf  # noqa: E402
from analyzer.scoring import score_apk  # noqa: E402
from tests.helpers import clean_result, trojan_result  # noqa: E402

SHA = "b" * 64


@pytest.fixture
def plain_pdf(monkeypatch):
    """Turn off PDF compression so the text can be searched in the raw bytes."""
    from reportlab import rl_config
    monkeypatch.setattr(rl_config, "pageCompression", 0)


def finished(result):
    result["info"] = {"package": "com.test", "version": "1", "min_sdk": "21", "target_sdk": "33"}
    result["risk"] = score_apk(result)
    result["mitre"] = map_to_mitre(result)
    return result


def test_pdf_is_generated_for_a_risky_apk():
    pdf = build_pdf("bad.apk", SHA, finished(trojan_result()))
    assert pdf.startswith(b"%PDF") and len(pdf) > 3000


def test_pdf_is_generated_for_a_clean_apk():
    assert build_pdf("clean.apk", SHA, finished(clean_result())).startswith(b"%PDF")


def test_pdf_handles_unicode_and_very_long_values():
    r = finished(trojan_result())
    r["iocs"]["urls"] = ["http://evil.ru/" + "A" * 500, "http://caf\u00e9-\u4e2d\u6587.ru/x"]
    r["iocs"]["domains"] = ["\u4e2d\u6587.ru", "<script>.com"]
    assert build_pdf("we<ird>&name.apk", SHA, r).startswith(b"%PDF")


def test_pdf_includes_threat_intel_when_given(plain_pdf):
    intel = [{"source": "VirusTotal", "status": "found", "summary": "41/70 engines"}]
    with_intel = build_pdf("bad.apk", SHA, finished(trojan_result()), intel)
    without = build_pdf("bad.apk", SHA, finished(trojan_result()))
    assert b"41/70 engines" in with_intel
    assert b"41/70 engines" not in without


def test_pdf_includes_ai_summary_and_correlations(plain_pdf):
    r = finished(trojan_result())
    plain = build_pdf("bad.apk", SHA, r)
    summary = {"text": "Why: sms_with_network.", "source": "ai", "model": "llama3.2:3b",
               "unverified": ["T1999"]}
    with_summary = build_pdf("bad.apk", SHA, r, ai_summary=summary)
    assert b"llama3.2:3b" in with_summary and b"T1999" in with_summary
    assert b"llama3.2:3b" not in plain
    assert b"Correlated findings" in plain  # deterministic section is always present


def test_pdf_marks_a_template_summary_as_rule_based(plain_pdf):
    summary = {"text": "Risk score 5/100.", "source": "template", "model": None, "unverified": []}
    pdf = build_pdf("clean.apk", SHA, finished(clean_result()), ai_summary=summary)
    assert b"rule-based summary" in pdf and b"AI-generated" not in pdf
import pytest

pytest.importorskip("reportlab")

from analyzer.mitre import map_to_mitre  # noqa: E402
from analyzer.report import build_pdf  # noqa: E402
from analyzer.scoring import score_apk  # noqa: E402
from tests.helpers import clean_result, trojan_result  # noqa: E402

SHA = "b" * 64


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


def test_pdf_includes_threat_intel_when_given():
    intel = [{"source": "VirusTotal", "status": "found", "summary": "41/70 engines"}]
    with_intel = build_pdf("bad.apk", SHA, finished(trojan_result()), intel)
    without = build_pdf("bad.apk", SHA, finished(trojan_result()))
    assert len(with_intel) > len(without)

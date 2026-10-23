"""Integration test: runs the full pipeline on any APK found in samples/."""
import glob

import pytest

SAMPLES = sorted(glob.glob("samples/*.apk"))
pytestmark = pytest.mark.skipif(not SAMPLES, reason="no APKs in samples/")

EXPECTED_KEYS = {"info", "permissions", "components", "iocs", "certificate",
                 "evasion", "libraries", "risk", "mitre"}


@pytest.mark.parametrize("path", SAMPLES)
def test_full_pipeline_on_real_apk(path):
    from analyze import analyze
    result = analyze(path)
    assert EXPECTED_KEYS <= set(result)
    assert 0 <= result["risk"]["score"] <= 100
    assert result["risk"]["level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert result["info"]["package"]

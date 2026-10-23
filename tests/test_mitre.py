from analyzer.mitre import TECHNIQUES, map_to_mitre
from tests.helpers import clean_result, perm, trojan_result


def ids(result):
    return {t["technique_id"] for t in map_to_mitre(result)}


def test_trojan_maps_expected_techniques():
    assert {"T1636.004", "T1453", "T1407", "T1633.001", "T1437.001", "T1406"} <= ids(trojan_result())


def test_clean_app_maps_nothing():
    assert map_to_mitre(clean_result()) == []


def test_info_findings_are_not_mapped():
    result = clean_result()
    result["evasion"] = [{"indicator": "native_code_loading", "severity": "info", "evidence": []}]
    assert map_to_mitre(result) == []


def test_common_permission_has_low_confidence():
    result = clean_result()
    result["permissions"] = [perm("SYSTEM_ALERT_WINDOW")]
    t = map_to_mitre(result)[0]
    assert t["technique_id"] == "T1417.002"
    assert t["confidence"] == "low"


def test_sensitive_permission_has_medium_confidence():
    result = clean_result()
    result["permissions"] = [perm("READ_SMS")]
    assert map_to_mitre(result)[0]["confidence"] == "medium"


def test_same_technique_merges_evidence_from_several_sources():
    result = clean_result()
    result["evasion"] = [
        {"indicator": "anti_debugging", "severity": "high", "evidence": ["tracerpid"]},
        {"indicator": "emulator_detection", "severity": "high", "evidence": ["qemu"]},
    ]
    found = [t for t in map_to_mitre(result) if t["technique_id"] == "T1633.001"]
    assert len(found) == 1
    assert set(found[0]["evidence"]) == {"tracerpid", "qemu"}


def test_urls_are_built_correctly():
    result = clean_result()
    result["permissions"] = [perm("READ_SMS")]
    assert map_to_mitre(result)[0]["url"] == "https://attack.mitre.org/techniques/T1636/004/"


def test_every_technique_has_name_and_tactic():
    for tid, (name, tactic) in TECHNIQUES.items():
        assert tid.startswith("T") and name and tactic

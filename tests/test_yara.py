from typing import Any

import pytest

from analyzer.yara_gen import generate_yara
from tests.helpers import clean_result, trojan_result

SHA = "a" * 64


def with_meta(result: dict[str, Any], package: str, score: int, level: str) -> dict[str, Any]:
    """Add the fields that generate_yara() reads besides the findings."""
    result["info"] = {"package": package}
    result["risk"] = {"score": score, "level": level}
    result["mitre"] = []
    return result


def base() -> dict[str, Any]:
    return with_meta(clean_result(), "com.test.app", 5, "LOW")


def test_clean_app_gets_no_rule():
    assert generate_yara(base(), SHA) is None


def test_single_generic_behaviour_gets_no_rule():
    r = base()
    r["evasion"] = [{"indicator": "dynamic_code_loading", "severity": "medium", "evidence": ["dexclassloader"]}]
    assert generate_yara(r, SHA) is None


def test_ioc_app_gets_rule_with_metadata():
    r = base()
    r["iocs"] = {"urls": ["http://evil-c2.ru/gate.php"], "ips": ["185.220.101.4"], "domains": []}
    rule = generate_yara(r, SHA)
    assert rule is not None
    assert "http://evil-c2.ru/gate.php" in rule
    assert SHA in rule
    assert "uint32(0) == 0x0A786564" in rule


def test_special_characters_are_escaped():
    r = base()
    r["iocs"] = {"urls": ['http://evil.ru/a"b\\c'], "ips": [], "domains": []}
    rule = generate_yara(r, SHA)
    assert rule is not None
    assert 'a\\"b\\\\c' in rule


def test_generated_rule_compiles_and_matches():
    yara = pytest.importorskip("yara")
    r = with_meta(trojan_result(), "com.bad.app", 90, "CRITICAL")
    rule = generate_yara(r, SHA)
    assert rule is not None
    compiled = yara.compile(source=rule)
    assert compiled.match(data=b"dex\n035\x00 ... http://evil-c2.ru/gate.php ...")
    assert compiled.match(data=b"dex\n035\x00 goldfish qemu ranchu")
    assert not compiled.match(data=b"dex\n035\x00 nothing suspicious")
    assert not compiled.match(data=b"PK\x03\x04 http://evil-c2.ru/gate.php")


def test_rule_is_named_after_kavach_and_the_package():
    r = base()
    r["iocs"] = {"urls": ["http://evil-c2.ru/gate.php"], "ips": [], "domains": []}
    rule = generate_yara(r, SHA)
    assert rule is not None
    assert rule.startswith("rule Kavach_com_test_app_")
    assert 'author = "Kavach"' in rule
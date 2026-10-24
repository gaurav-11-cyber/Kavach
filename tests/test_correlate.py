from analyzer.correlate import compare_apks, correlate_findings
from tests.helpers import clean_result, finish, perm, trojan_result


def ids(result):
    return {c["id"] for c in correlate_findings(result)}


def test_clean_app_has_no_correlations():
    assert correlate_findings(finish(clean_result())) == []


def test_trojan_like_app_has_the_expected_correlations():
    found = ids(finish(trojan_result()))
    assert {"sms_to_network", "staged_payload", "takeover_toolkit", "boot_persistent_loader"} <= found
    assert "evasion_cluster" not in found  # the sample has only one anti-analysis check


def test_sms_without_network_indicator_is_only_medium():
    r = clean_result()
    r["permissions"] = [perm("READ_SMS"), perm("INTERNET", False)]
    found = correlate_findings(finish(r))
    assert [c["id"] for c in found] == ["sms_with_internet"]
    assert found[0]["severity"] == "medium"


def test_correlations_are_sorted_high_first_and_carry_evidence():
    found = correlate_findings(finish(trojan_result()))
    order = {"high": 0, "medium": 1, "low": 2}
    assert [order[c["severity"]] for c in found] == sorted(order[c["severity"]] for c in found)
    assert all(c["evidence"] and c["why"] for c in found)


def test_two_anti_analysis_checks_form_a_cluster():
    r = clean_result()
    r["evasion"] = [
        {"indicator": "emulator_detection", "severity": "high", "description": "", "evidence": ["qemu"]},
        {"indicator": "anti_debugging", "severity": "medium", "description": "", "evidence": ["tracerpid"]},
    ]
    assert "evasion_cluster" in ids(finish(r))


def test_single_anti_analysis_check_is_not_a_cluster():
    r = clean_result()
    r["evasion"] = [{"indicator": "emulator_detection", "severity": "high", "description": "", "evidence": ["x"]}]
    assert "evasion_cluster" not in ids(finish(r))


def test_correlations_do_not_change_the_score():
    r = finish(trojan_result())
    before = r["risk"]["score"]
    correlate_findings(r)
    assert r["risk"]["score"] == before


def _item(label, package, hosts=(), cert=None, debug=False, libs=()):
    r = clean_result()
    r["iocs"] = {"urls": [f"http://{h}/x" for h in hosts], "ips": [], "domains": []}
    r["certificate"]["certificates"] = [{"sha256": cert, "debug_certificate": debug}] if cert else []
    r["libraries"] = [{"name": n, "category": "framework"} for n in libs]
    return {"label": label, "result": finish(r, package)}


def test_shared_c2_host_is_a_strong_link():
    pairs = compare_apks([_item("a", "p.a", ["evil-c2.ru"]), _item("b", "p.b", ["evil-c2.ru"])])
    assert pairs[0]["verdict"] == "strong link"
    assert "shared network indicator: evil-c2.ru" in pairs[0]["strong"]


def test_shared_debug_certificate_is_not_a_strong_link():
    pairs = compare_apks([_item("a", "p.a", cert="ab" * 32, debug=True),
                          _item("b", "p.b", cert="ab" * 32, debug=True)])
    assert pairs[0]["verdict"] != "strong link"


def test_shared_real_certificate_is_a_strong_link():
    pairs = compare_apks([_item("a", "p.a", cert="cd" * 32), _item("b", "p.b", cert="cd" * 32)])
    assert pairs[0]["verdict"] == "strong link"


def test_common_libraries_only_is_a_weak_similarity():
    pairs = compare_apks([_item("a", "p.a", libs=["AndroidX"]), _item("b", "p.b", libs=["AndroidX"])])
    assert pairs[0]["verdict"] == "weak similarity" and not pairs[0]["strong"]


def test_unrelated_apks_have_no_overlap():
    pairs = compare_apks([_item("a", "p.a"), _item("b", "p.b")])
    assert pairs[0]["verdict"] == "no overlap"


def test_strong_links_are_listed_first():
    items = [_item("a", "p.a", ["x.ru"]), _item("b", "p.b", ["x.ru"]), _item("c", "p.c")]
    assert compare_apks(items)[0]["verdict"] == "strong link"


def test_obfuscation_alone_is_not_correlated_but_with_a_loader_it_is():
    r = clean_result()
    r["evasion"] = [{"indicator": "name_obfuscation", "severity": "low", "description": "", "evidence": ["28%"]}]
    assert "obfuscated_loader" not in ids(finish(r))
    r["evasion"].append({"indicator": "dynamic_code_loading", "severity": "medium", "description": "",
                         "evidence": ["dexclassloader"]})
    assert "obfuscated_loader" in ids(finish(r))
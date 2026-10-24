from analyzer.scoring import GROUP_CAPS, _level, score_apk
from tests.helpers import clean_result, perm, trojan_result


def rules(result):
    return {row["rule"] for row in result["breakdown"]}


def test_clean_app_scores_low():
    r = score_apk(clean_result())
    assert r["level"] == "LOW"
    assert r["score"] < 10


def test_trojan_like_app_scores_critical():
    r = score_apk(trojan_result())
    assert r["level"] == "CRITICAL"
    assert {"sms_with_network", "accessibility_service", "debug_certificate"} <= rules(r)


def test_every_point_has_a_reason():
    for row in score_apk(trojan_result())["breakdown"]:
        assert row["points"] > 0
        assert row["reason"]


def test_breakdown_sorted_by_points():
    points = [row["points"] for row in score_apk(trojan_result())["breakdown"]]
    assert points == sorted(points, reverse=True)


def test_score_never_exceeds_100():
    assert score_apk(trojan_result())["score"] <= 100


def test_level_bands():
    assert _level(29) == "LOW"
    assert _level(30) == "MEDIUM"
    assert _level(59) == "MEDIUM"
    assert _level(60) == "HIGH"
    assert _level(79) == "HIGH"
    assert _level(80) == "CRITICAL"


def test_group_cap_limits_evasion_points():
    result = clean_result()
    result["evasion"] = [
        {"indicator": f"x{i}", "severity": "high", "description": "d", "evidence": []}
        for i in range(10)
    ]
    r = score_apk(result)
    evasion_points = sum(row["points"] for row in r["breakdown"] if row["group"] == "evasion")
    assert evasion_points == GROUP_CAPS["evasion"]


def test_single_weak_signals_do_not_make_a_browser_critical():
    """Regression: a browser used to score 100 from stray strings."""
    result = clean_result()
    result["permissions"] += [perm("SYSTEM_ALERT_WINDOW"), perm("READ_EXTERNAL_STORAGE"),
                              perm("WRITE_EXTERNAL_STORAGE")]
    result["evasion"] = [
        {"indicator": "dynamic_code_loading", "severity": "medium", "description": "d", "evidence": []},
        {"indicator": "emulator_detection", "severity": "low", "description": "e", "evidence": []},
        {"indicator": "reflection", "severity": "info", "description": "r", "evidence": []},
    ]
    assert score_apk(result)["level"] == "LOW"


def test_bare_domains_are_not_scored():
    result = clean_result()
    result["iocs"]["domains"] = ["the.com", "thing.org", "people.in"]
    assert score_apk(result)["score"] == score_apk(clean_result())["score"]


def test_protected_exported_component_not_counted():
    # the clean receiver is exported but protected by a permission
    assert "exported_components" not in rules(score_apk(clean_result()))


def test_unprotected_exported_service_is_counted():
    result = clean_result()
    result["components"].append(
        {"type": "service", "name": "x.S", "exported": True, "permission": None})
    assert "exported_components" in rules(score_apk(result))


def test_a_few_https_hosts_do_not_make_a_normal_app_risky():
    """Regression: a chess app that mentions three web hosts scored MEDIUM (36)."""
    result = clean_result()
    result["permissions"].append(perm("ACCESS_FINE_LOCATION"))
    result["iocs"]["urls"] = ["https://database.lichess.org/x", "https://git.skysparkle.cc/y",
                              "https://iconbuddy.com/z"]
    r = score_apk(result)
    assert r["level"] == "LOW"
    assert r["score"] < 15


def test_hosts_add_at_most_nine_points():
    result = clean_result()
    result["iocs"]["urls"] = [f"https://host{i}.example.org/x" for i in range(20)]
    host_rows = [row for row in score_apk(result)["breakdown"] if row["rule"] == "external_hosts"]
    assert host_rows[0]["points"] == 9


def test_raw_public_ips_still_weigh_more_than_hosts():
    result = clean_result()
    result["iocs"]["ips"] = ["185.220.101.4"]
    rows = {row["rule"]: row["points"] for row in score_apk(result)["breakdown"]}
    assert rows["hardcoded_public_ips"] == 10
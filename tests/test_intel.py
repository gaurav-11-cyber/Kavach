import urllib.error

import pytest

from analyzer import intel

SHA = "a" * 64


@pytest.fixture(autouse=True)
def keys(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-test-key")
    monkeypatch.setenv("MB_AUTH_KEY", "mb-test-key")


def fake_request(status, body, calls=None):
    def _request(url, headers, data=None):
        if calls is not None:
            calls.append((url, headers, data))
        return status, body
    return _request


VT_FOUND = {"data": {"attributes": {
    "last_analysis_stats": {"malicious": 41, "harmless": 0, "undetected": 29},
    "popular_threat_classification": {"suggested_threat_label": "trojan.banker"}}}}


def test_virustotal_found(monkeypatch):
    monkeypatch.setattr(intel, "_request", fake_request(200, VT_FOUND))
    r = intel.lookup_virustotal(SHA)
    assert r["status"] == "found"
    assert "41/70" in r["summary"] and "trojan.banker" in r["summary"]
    assert SHA in r["link"]


def test_virustotal_unknown_hash(monkeypatch):
    monkeypatch.setattr(intel, "_request", fake_request(404, {"error": {}}))
    assert intel.lookup_virustotal(SHA)["status"] == "not_found"


def test_virustotal_http_error(monkeypatch):
    monkeypatch.setattr(intel, "_request", fake_request(429, None))
    r = intel.lookup_virustotal(SHA)
    assert r["status"] == "error" and "429" in r["summary"]


def test_missing_keys_do_not_hit_the_network(monkeypatch):
    monkeypatch.delenv("VT_API_KEY")
    monkeypatch.delenv("MB_AUTH_KEY")
    calls = []
    monkeypatch.setattr(intel, "_request", fake_request(200, {}, calls))
    results = intel.lookup_hash(SHA)
    assert [r["status"] for r in results] == ["no_key", "no_key"]
    assert calls == []


def test_network_failure_is_reported_not_raised(monkeypatch):
    def boom(url, headers, data=None):
        raise urllib.error.URLError("offline")
    monkeypatch.setattr(intel, "_request", boom)
    assert all(r["status"] == "error" for r in intel.lookup_hash(SHA))


def test_malwarebazaar_found(monkeypatch):
    body = {"query_status": "ok", "data": [{"signature": "Hydra", "tags": ["apk", "banker"],
                                            "first_seen": "2026-01-01 10:00:00"}]}
    monkeypatch.setattr(intel, "_request", fake_request(200, body))
    r = intel.lookup_malwarebazaar(SHA)
    assert r["status"] == "found" and "Hydra" in r["summary"] and "banker" in r["summary"]


def test_malwarebazaar_not_found(monkeypatch):
    monkeypatch.setattr(intel, "_request", fake_request(200, {"query_status": "hash_not_found"}))
    assert intel.lookup_malwarebazaar(SHA)["status"] == "not_found"


def test_only_the_hash_is_sent(monkeypatch):
    calls = []
    monkeypatch.setattr(intel, "_request", fake_request(200, VT_FOUND, calls))
    intel.lookup_hash(SHA)
    vt_url, vt_headers, vt_data = calls[0]
    assert vt_url.endswith(SHA) and vt_data is None
    mb_url, mb_headers, mb_data = calls[1]
    assert mb_data == {"query": "get_info", "hash": SHA}


def test_lookup_hash_returns_both_sources(monkeypatch):
    monkeypatch.setattr(intel, "_request", fake_request(404, None))
    assert [r["source"] for r in intel.lookup_hash(SHA)] == ["VirusTotal", "MalwareBazaar"]

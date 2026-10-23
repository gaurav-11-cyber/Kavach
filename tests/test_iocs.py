from analyzer.iocs import extract_iocs
from tests.helpers import FakeApk


def extract(text):
    return extract_iocs(FakeApk(dex=text.encode()))


def test_real_c2_url_and_public_ip_are_kept():
    r = extract("http://evil-c2.ru/gate.php 185.220.101.4")
    assert "http://evil-c2.ru/gate.php" in r["urls"]
    assert "185.220.101.4" in r["ips"]


def test_ip_as_url_host_is_kept():
    assert extract("http://45.33.32.156/x.php")["urls"] == ["http://45.33.32.156/x.php"]


def test_private_and_emulator_ips_are_dropped():
    r = extract("10.0.2.2 192.168.1.5 127.0.0.1 172.16.0.1 0.0.0.0")
    assert r["ips"] == []


def test_junk_urls_are_dropped():
    r = extract("http://according http://www.css http://filesystem.local http://html4/loose.dtd")
    assert r["urls"] == []


def test_benign_platform_urls_are_dropped():
    r = extract("http://schemas.android.com/apk/res/android https://github.com/foo/bar "
                "https://developer.android.com/x http://ns.adobe.com/xap/1.0/")
    assert r["urls"] == []


def test_raw_github_host_is_not_treated_as_benign():
    assert extract("https://raw.githubusercontent.com/x/payload.bin")["urls"]


def test_java_package_names_are_not_domains():
    r = extract("androidx.appcompat.app android.app org.openjsse.net libcore.io")
    assert r["domains"] == []


def test_no_duplicates_and_sorted():
    r = extract("185.220.101.4 185.220.101.4 8.8.8.8")
    assert r["ips"] == ["185.220.101.4", "8.8.8.8"]

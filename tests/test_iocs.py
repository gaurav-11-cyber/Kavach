from analyzer.iocs import extract_iocs
from tests.helpers import FakeApk


def dex_strings(*strings):
    """Bytes laid out like DEX string data: [length][text][NUL] for each string."""
    return b"".join(bytes([len(t.encode())]) + t.encode() + b"\x00" for t in strings)


def extract(*strings):
    return extract_iocs(FakeApk(dex=dex_strings(*strings)))


def test_real_c2_url_and_public_ip_are_kept():
    r = extract("http://evil-c2.ru/gate.php", "185.220.101.4")
    assert "http://evil-c2.ru/gate.php" in r["urls"]
    assert "185.220.101.4" in r["ips"]


def test_ip_as_url_host_is_kept():
    assert extract("http://45.33.32.156/x.php")["urls"] == ["http://45.33.32.156/x.php"]


def test_private_and_emulator_ips_are_dropped():
    r = extract("10.0.2.2", "192.168.1.5", "127.0.0.1", "172.16.0.1", "0.0.0.0")
    assert r["ips"] == []


def test_junk_urls_are_dropped():
    r = extract("http://according", "http://www.css", "http://filesystem.local", "http://html4/loose.dtd")
    assert r["urls"] == []


def test_benign_platform_urls_are_dropped():
    r = extract("http://schemas.android.com/apk/res/android", "https://github.com/foo/bar",
                "https://developer.android.com/x", "http://ns.adobe.com/xap/1.0/")
    assert r["urls"] == []


def test_raw_github_host_is_not_treated_as_benign():
    assert extract("https://raw.githubusercontent.com/x/payload.bin")["urls"]


def test_java_package_names_are_not_domains():
    r = extract("androidx.appcompat.app", "android.app", "org.openjsse.net", "libcore.io")
    assert r["domains"] == []


def test_no_duplicates_and_sorted():
    r = extract("185.220.101.4", "185.220.101.4", "8.8.8.8")
    assert r["ips"] == ["185.220.101.4", "8.8.8.8"]


def test_numbers_inside_svg_path_data_are_not_ips():
    """Regression: icon path data produced fake IPs 3.5.7.7 and 5.38.8.97."""
    svg = ("M15 14c.2-1 .7-1.7 1.5-2.5 1-.9 1.5-2.2 1.5-3.5A6 6 0 0 0 6 8c0 1 .2 2.2 1.5 3.5"
           ".7.7 1.3 1.5 1.5 2.5 3.5.7.7 1.3")
    svg2 = "M21.2 8.4c.5.38.8.97.8 1.6v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V10a2 2 0 0 1 .8-1.6"
    assert extract(svg, svg2)["ips"] == []
    assert extract("a 3.5.7.7 b 5.38.8.97 c")["ips"] == []


def test_ip_with_port_is_found_as_a_whole_string():
    assert extract("185.220.101.4:8080")["ips"] == ["185.220.101.4"]


def test_ip_inside_a_longer_string_is_not_counted():
    assert extract("connect to 185.220.101.4 now")["ips"] == []


def test_well_known_ad_and_platform_hosts_are_dropped():
    r = extract("https://googleads.g.doubleclick.net/mads/x.js", "http://www.google-analytics.com",
                "https://www.paypal.com/login", "https://login.live.com/oauth")
    assert r["urls"] == []
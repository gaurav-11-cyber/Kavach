"""IoC extraction: URLs, IPs and domains from the DEX files of an APK."""
import re
from urllib.parse import urlparse
 
URL_RE = re.compile(rb"https?://[\w\-\.~:/?#@!$&'()*+,;=%]{4,200}")
IP_RE = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
# Ambiguous TLDs like app, dev, me, co, to are left out on purpose:
# they match Java package names (androidx.appcompat.app) and cause noise.
TLDS = (
    "com|net|org|io|info|biz|xyz|top|ru|cn|in|tk|ml|ga|cf|gq|site|"
    "online|club|cc|pw|shop|live|vip"
)
DOMAIN_RE = re.compile(
    rb"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:" + TLDS.encode() + rb")\b"
)
 
# Harmless domains found in almost every app
BENIGN_DOMAINS = {
    "android.com", "googleapis.com", "google.com", "gstatic.com",
    "w3.org", "apache.org", "github.com", "example.com",
    "kotlinlang.org", "xmlpull.org", "mozilla.org", "schema.org",
}
 
# Java/Kotlin package fragments that look like domains
PACKAGE_HINTS = ("androidx", "android.", "kotlin", "java.", "javax.")
 
 
def _is_benign(host):
    return any(host == d or host.endswith("." + d) for d in BENIGN_DOMAINS)
 
 
def _looks_like_package(domain):
    return any(hint in domain for hint in PACKAGE_HINTS)
 
 
def _valid_ip(ip):
    # skip unspecified/loopback and version-like noise
    return not ip.startswith(("0.", "127.", "255."))
 
 
def extract_iocs(apk):
    urls, ips, domains = set(), set(), set()
    for dex in apk.get_all_dex():
        for m in URL_RE.findall(dex):
            url = m.decode("utf-8", "ignore")
            host = (urlparse(url).hostname or "").lower()
            if host and not _is_benign(host):
                urls.add(url)
        for m in IP_RE.findall(dex):
            ip = m.decode("utf-8", "ignore")
            if _valid_ip(ip):
                ips.add(ip)
        for m in DOMAIN_RE.findall(dex):
            domain = m.decode("utf-8", "ignore").lower()
            if not _is_benign(domain) and not _looks_like_package(domain):
                domains.add(domain)
    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains),
    }
 
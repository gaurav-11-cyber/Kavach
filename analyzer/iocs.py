"""IoC extraction: URLs, IPs and domains from the DEX files of an APK."""
import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(rb"https?://[\w\-\.~:/?#@!$&'()*+,;=%]{4,200}")
# An IP counts only when it is a whole DEX string: [length byte][ip or ip:port][NUL].
# Searching raw bytes for a.b.c.d also matches numbers inside SVG path data and text.
IP_RE = re.compile(
    rb"(?<![\d.])((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?::\d{1,5})?(?=\x00)"
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
HOST_RE = re.compile(r"^(?:[a-z0-9-]+\.)+(?:" + TLDS + r")$")

# Harmless domains found in many apps (library docs, schemas, vendors)
BENIGN_DOMAINS = {
    "android.com", "googleapis.com", "google.com", "gstatic.com",
    "w3.org", "apache.org", "github.com", "example.com",
    "kotlinlang.org", "xmlpull.org", "mozilla.org", "schema.org",
    "adobe.com", "xml.org", "jetbrains.com", "swmansion.com",
    "facebook.com", "microsoft.com", "oracle.com", "openssl.org",
}

# Java/Kotlin package fragments that look like domains
PACKAGE_HINTS = ("androidx", "android.", "kotlin", "java.", "javax.", "libcore")
PACKAGE_PREFIXES = ("org.", "com.", "net.", "io.", "edu.")


def _is_benign(host):
    return any(host == d or host.endswith("." + d) for d in BENIGN_DOMAINS)


def _looks_like_package(domain):
    return domain.startswith(PACKAGE_PREFIXES) or any(h in domain for h in PACKAGE_HINTS)


def _is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _valid_url_host(host):
    """Real hostname with a known TLD, or a public IP address."""
    return bool(host) and (HOST_RE.match(host) is not None or _is_public_ip(host))


def extract_iocs(apk):
    urls, ips, domains = set(), set(), set()
    for dex in apk.get_all_dex():
        for m in URL_RE.findall(dex):
            url = m.decode("utf-8", "ignore")
            host = (urlparse(url).hostname or "").lower()
            if _valid_url_host(host) and not _is_benign(host):
                urls.add(url)
        for m in IP_RE.finditer(dex):
            whole = m.group(0)
            # the byte before the string is its length: the string must be exactly the IP
            if m.start() == 0 or dex[m.start() - 1] != len(whole):
                continue
            ip = m.group(1).decode("ascii", "ignore")
            if _is_public_ip(ip):
                ips.add(ip)
        for m in DOMAIN_RE.findall(dex):
            domain = m.decode("utf-8", "ignore").lower()
            if not _is_benign(domain) and not _looks_like_package(domain):
                domains.add(domain)
    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "domains": sorted(domains),  # low confidence: informational, not scored
    }
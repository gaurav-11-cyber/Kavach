"""Explainable, rule-based risk scoring.

Every point in the score comes from a named rule, so an analyst can see
exactly why an APK was rated the way it was. Each group of rules has a cap,
so one noisy area cannot push a benign app to 100 on its own.
"""
from urllib.parse import urlparse

SEVERITY_POINTS = {"high": 20, "medium": 10, "low": 3, "info": 0}

# max points each group of rules can contribute
GROUP_CAPS = {
    "permissions": 45, "exposure": 15, "ioc": 35,
    "certificate": 20, "evasion": 50, "libraries": 9,
}

SMS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
}
COMMON_PERMS = {  # sensitive but normal in many apps: low weight
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
}


class _Board:
    def __init__(self):
        self.rows = []
        self.used = {}

    def add(self, group, rule, points, reason, evidence=None):
        room = GROUP_CAPS[group] - self.used.get(group, 0)
        points = min(points, room)
        if points <= 0:
            return
        self.used[group] = self.used.get(group, 0) + points
        self.rows.append({
            "group": group, "rule": rule, "points": points,
            "reason": reason, "evidence": evidence or [],
        })


def _level(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def score_apk(result):
    b = _Board()
    perms = {p["name"] for p in result.get("permissions", [])}
    dangerous = {p["name"] for p in result.get("permissions", []) if p["dangerous"]}

    # --- Permissions ---
    sms = sorted(perms & SMS_PERMS)
    if sms and "android.permission.INTERNET" in perms:
        b.add("permissions", "sms_with_network", 20,
              "Can read or send SMS and has network access (possible SMS stealer)", sms)
    elif sms:
        b.add("permissions", "sms_access", 10, "Requests SMS permissions", sms)
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
        b.add("permissions", "accessibility_service", 20,
              "Accessibility service access is often abused by banking trojans",
              ["BIND_ACCESSIBILITY_SERVICE"])
    if "android.permission.BIND_DEVICE_ADMIN" in perms:
        b.add("permissions", "device_admin", 20, "Requests device admin rights",
              ["BIND_DEVICE_ADMIN"])
    if "android.permission.SYSTEM_ALERT_WINDOW" in perms:
        b.add("permissions", "overlay", 5, "Can draw over other apps (overlay attacks)",
              ["SYSTEM_ALERT_WINDOW"])
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        b.add("permissions", "install_packages", 10, "Can request to install other apps",
              ["REQUEST_INSTALL_PACKAGES"])
    if "android.permission.RECEIVE_BOOT_COMPLETED" in perms:
        b.add("permissions", "persistence", 5, "Starts automatically after reboot",
              ["RECEIVE_BOOT_COMPLETED"])
    handled = SMS_PERMS | {
        "android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    }
    rest = sorted(dangerous - handled)
    common = [p for p in rest if p in COMMON_PERMS]
    unusual = [p for p in rest if p not in COMMON_PERMS]
    b.add("permissions", "sensitive_permissions", len(unusual) * 3 + len(common) * 1,
          f"{len(rest)} other sensitive permissions requested", rest)

    # --- Exposed components ---
    exposed = [c["name"] for c in result.get("components", [])
               if c["exported"] and not c["permission"] and c["type"] != "activity"]
    b.add("exposure", "exported_components", len(exposed) * 5,
          "Exported services, receivers or providers without a protecting permission", exposed)

    # --- IoCs (bare domain strings are low confidence and not scored) ---
    iocs = result.get("iocs", {})
    b.add("ioc", "hardcoded_public_ips", len(iocs.get("ips", [])) * 10,
          "Hardcoded public IP addresses in code", iocs.get("ips", []))
    hosts = sorted({urlparse(u).hostname for u in iocs.get("urls", []) if urlparse(u).hostname})
    # Most apps mention a few web hosts (APIs, docs, repos), so hosts alone are only a weak signal.
    # Raw public IPs and cleartext HTTP weigh more. Correlated findings and hash lookup cover the rest.
    b.add("ioc", "external_hosts", min(len(hosts) * 3, 9),
          "Network hosts referenced by URLs in code that are not common platform domains", hosts)
    cleartext = [u for u in iocs.get("urls", []) if u.startswith("http://")]
    b.add("ioc", "cleartext_urls", len(cleartext) * 5, "Unencrypted HTTP URLs in code", cleartext)

    # --- Certificate ---
    cert = result.get("certificate", {})
    certs = cert.get("certificates", [])
    if any(c.get("debug_certificate") for c in certs):
        b.add("certificate", "debug_certificate", 15, "Signed with an Android debug certificate")
    if any(c.get("expired") for c in certs):
        b.add("certificate", "expired_certificate", 5, "Signing certificate has expired")
    if cert and not (cert.get("signed_v2") or cert.get("signed_v3")):
        b.add("certificate", "legacy_signing", 5, "Only signed with legacy v1 scheme")
    if cert and not certs:
        b.add("certificate", "unsigned", 10, "No signing certificate found")

    # --- Evasion ---
    found = {f["indicator"] for f in result.get("evasion", [])}
    for f in result.get("evasion", []):
        b.add("evasion", f["indicator"], SEVERITY_POINTS.get(f["severity"], 0),
              f["description"], f.get("evidence", []))
    if "dynamic_code_loading" in found and "encrypted_or_hidden_payload" in found:
        b.add("evasion", "loader_with_hidden_payload", 20,
              "Runtime code loading together with a hidden or encrypted payload")

    # --- Libraries ---
    ads = [l["name"] for l in result.get("libraries", []) if l["category"] == "ads_tracking"]
    b.add("libraries", "ad_tracking_sdks", len(ads) * 3, "Ad or tracking SDKs included", ads)

    score = min(sum(x["points"] for x in b.rows), 100)
    rows = sorted(b.rows, key=lambda x: -x["points"])
    return {"score": score, "level": _level(score), "breakdown": rows}
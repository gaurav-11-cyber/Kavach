"""Explainable, rule-based risk scoring.

Every point in the score comes from a named rule, so an analyst can see
exactly why an APK was rated the way it was.
"""

SEVERITY_POINTS = {"high": 20, "medium": 10, "low": 3}

SMS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
}


def _add(breakdown, rule, points, reason, evidence=None):
    if points > 0:
        breakdown.append({
            "rule": rule, "points": points, "reason": reason,
            "evidence": evidence or [],
        })


def _level(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def score_apk(result):
    b = []
    perms = {p["name"] for p in result.get("permissions", [])}
    dangerous = sorted(p["name"] for p in result.get("permissions", []) if p["dangerous"])

    # --- Permissions ---
    sms = sorted(perms & SMS_PERMS)
    if sms and "android.permission.INTERNET" in perms:
        _add(b, "sms_with_network", 20,
             "Can read or send SMS and has network access (possible SMS stealer)", sms)
    elif sms:
        _add(b, "sms_access", 10, "Requests SMS permissions", sms)
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in perms:
        _add(b, "accessibility_service", 20,
             "Accessibility service access is often abused by banking trojans",
             ["BIND_ACCESSIBILITY_SERVICE"])
    if "android.permission.BIND_DEVICE_ADMIN" in perms:
        _add(b, "device_admin", 20, "Requests device admin rights", ["BIND_DEVICE_ADMIN"])
    if "android.permission.SYSTEM_ALERT_WINDOW" in perms:
        _add(b, "overlay", 10, "Can draw over other apps (overlay attacks)", ["SYSTEM_ALERT_WINDOW"])
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms:
        _add(b, "install_packages", 10, "Can request to install other apps",
             ["REQUEST_INSTALL_PACKAGES"])
    if "android.permission.RECEIVE_BOOT_COMPLETED" in perms:
        _add(b, "persistence", 5, "Starts automatically after reboot", ["RECEIVE_BOOT_COMPLETED"])
    special = {"android.permission.READ_SMS", "android.permission.SEND_SMS",
               "android.permission.RECEIVE_SMS", "android.permission.BIND_ACCESSIBILITY_SERVICE",
               "android.permission.BIND_DEVICE_ADMIN", "android.permission.SYSTEM_ALERT_WINDOW",
               "android.permission.REQUEST_INSTALL_PACKAGES",
               "android.permission.RECEIVE_BOOT_COMPLETED"}
    other = [p for p in dangerous if p not in special]
    _add(b, "dangerous_permissions", min(len(other) * 3, 15),
         f"{len(other)} other sensitive permissions requested", other)

    # --- Exposed components ---
    exposed = [c["name"] for c in result.get("components", [])
               if c["exported"] and not c["permission"] and c["type"] != "activity"]
    _add(b, "exported_components", min(len(exposed) * 5, 15),
         "Exported services, receivers or providers without a protecting permission", exposed)

    # --- IoCs ---
    iocs = result.get("iocs", {})
    _add(b, "hardcoded_ips", min(len(iocs.get("ips", [])) * 10, 20),
         "Hardcoded IP addresses in code", iocs.get("ips", []))
    _add(b, "suspicious_domains", min(len(iocs.get("domains", [])) * 8, 24),
         "Domains found in code that are not common platform domains", iocs.get("domains", []))
    cleartext = [u for u in iocs.get("urls", []) if u.startswith("http://")]
    _add(b, "cleartext_urls", min(len(cleartext) * 5, 10),
         "Unencrypted HTTP URLs in code", cleartext)

    # --- Certificate ---
    cert = result.get("certificate", {})
    certs = cert.get("certificates", [])
    if any(c.get("debug_certificate") for c in certs):
        _add(b, "debug_certificate", 15, "Signed with an Android debug certificate")
    if any(c.get("expired") for c in certs):
        _add(b, "expired_certificate", 5, "Signing certificate has expired")
    if cert and not (cert.get("signed_v2") or cert.get("signed_v3")):
        _add(b, "legacy_signing", 5, "Only signed with legacy v1 scheme")
    if cert and not certs:
        _add(b, "unsigned", 10, "No signing certificate found")

    # --- Evasion ---
    for f in result.get("evasion", []):
        _add(b, f["indicator"], SEVERITY_POINTS.get(f["severity"], 0),
             f["description"], f.get("evidence", []))

    # --- Libraries ---
    ads = [l["name"] for l in result.get("libraries", []) if l["category"] == "ads_tracking"]
    _add(b, "ad_tracking_sdks", min(len(ads) * 3, 9), "Ad or tracking SDKs included", ads)

    score = min(sum(x["points"] for x in b), 100)
    b.sort(key=lambda x: -x["points"])
    return {"score": score, "level": _level(score), "breakdown": b}

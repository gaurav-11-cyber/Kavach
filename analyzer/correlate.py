"""Deterministic correlation of findings, and comparison of several APKs.

These rules find combinations of findings that deserve more attention than
any single finding. They do not change the risk score. The AI assistant
only explains what these rules (and the score) already found.
"""
from typing import Any
from urllib.parse import urlparse

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
ANTI_ANALYSIS = {"anti_debugging", "emulator_detection", "hooking_framework_detection"}


def _perms(result: dict[str, Any]) -> set[str]:
    return {p["name"].replace("android.permission.", "") for p in result.get("permissions", [])}


def _evasion(result: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {e["indicator"]: e for e in result.get("evasion", [])}


def network_artifacts(result: dict[str, Any]) -> set[str]:
    """External hosts (from URLs) and public IPs found in the code."""
    iocs = result.get("iocs", {})
    hosts = {urlparse(u).hostname for u in iocs.get("urls", []) if urlparse(u).hostname}
    return {h for h in hosts if h} | set(iocs.get("ips", []))


def correlate_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    perms, evasion, network = _perms(result), _evasion(result), sorted(network_artifacts(result))
    certs = result.get("certificate", {}).get("certificates", [])
    found: list[dict[str, Any]] = []

    def add(cid, title, severity, why, evidence, mitre):
        found.append({"id": cid, "title": title, "severity": severity, "why": why,
                      "evidence": list(evidence), "mitre": mitre})

    sms = sorted(perms & {"READ_SMS", "RECEIVE_SMS"})
    if sms and network:
        add("sms_to_network", "SMS access together with external network indicators", "high",
            "The app can read SMS and its code references external hosts or IPs. Together this fits "
            "SMS interception and exfiltration. Neither finding shows that on its own.",
            sms + network[:3], ["T1636.004", "T1437.001"])
    elif sms and "INTERNET" in perms:
        add("sms_with_internet", "SMS access with internet permission", "medium",
            "The app can read SMS and use the network, but no external host was found in the code.",
            sms + ["INTERNET"], ["T1636.004"])

    loader = evasion.get("dynamic_code_loading")
    hidden = evasion.get("encrypted_or_hidden_payload")
    raw_ips = sorted(set(result.get("iocs", {}).get("ips", [])))
    if loader and (hidden or raw_ips):
        evidence = list(loader.get("evidence", []))[:2]
        if hidden:
            evidence += hidden.get("evidence", [])[:2]
        evidence += raw_ips[:2]
        add("staged_payload", "Runtime code loading with a hidden payload or a hardcoded IP", "high",
            "The app loads code at runtime and also carries a hidden payload or a hardcoded public IP. "
            "This is the pattern of a staged payload.", evidence, ["T1407", "T1406", "T1437.001"])
    elif loader and network:
        add("loader_with_external_hosts", "Runtime code loading and external hosts in the same app",
            "medium", "The app can load code at runtime and refers to external hosts. This is common "
            "when an ad or analytics SDK is included, so check what is loaded and from where before "
            "drawing conclusions.",
            list(loader.get("evidence", []))[:1] + network[:2], ["T1407", "T1437.001"])

    obfuscated = evasion.get("name_obfuscation")
    if obfuscated and loader:
        add("obfuscated_loader", "Obfuscated code that also loads code at runtime", "medium",
            "Short, obfuscated class names alone are common in release builds. Combined with runtime "
            "code loading they make it harder to see what gets loaded.",
            list(obfuscated.get("evidence", []))[:1] + list(loader.get("evidence", []))[:1],
            ["T1406", "T1407"])

    takeover = sorted(perms & {"BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW",
                               "REQUEST_INSTALL_PACKAGES"})
    if "BIND_ACCESSIBILITY_SERVICE" in takeover and len(takeover) >= 2:
        add("takeover_toolkit", "Accessibility service combined with overlay or install rights",
            "high" if len(takeover) == 3 else "medium",
            "Accessibility control plus the ability to draw over other apps or install packages is the "
            "toolkit used by banking trojans to take over a device.",
            takeover, ["T1453", "T1417.002", "T1544"])

    cluster = sorted(i for i in ANTI_ANALYSIS if i in evasion
                     and evasion[i]["severity"] in ("medium", "high"))
    if len(cluster) >= 2:
        add("evasion_cluster", "Several anti-analysis checks together", "high",
            "More than one anti-analysis technique at once suggests the app tries to avoid sandboxes "
            "and analysts on purpose.", cluster, ["T1633.001"])

    if "RECEIVE_BOOT_COMPLETED" in perms and loader:
        add("boot_persistent_loader", "Starts at boot and loads code at runtime", "medium",
            "The app restarts after reboot and can fetch or load new code, so what it does can change "
            "over time.", ["RECEIVE_BOOT_COMPLETED"] + list(loader.get("evidence", []))[:1],
            ["T1624.001", "T1407"])

    if any(c.get("debug_certificate") for c in certs) and result.get("risk", {}).get("score", 0) >= 30:
        add("debug_signed_risky", "Debug certificate on an app with other risk indicators", "medium",
            "Production apps are not normally signed with a debug certificate. Combined with other "
            "indicators this suggests a repackaged or unofficial build.", ["debug certificate"], [])

    return sorted(found, key=lambda c: SEVERITY_ORDER[c["severity"]])


def compare_apks(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pairwise comparison. Strong links are specific shared items, weak links are common ones."""
    out = []
    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            a, b = items[i], items[j]
            ra, rb = a["result"], b["result"]
            strong, weak = [], []

            for host in sorted(network_artifacts(ra) & network_artifacts(rb)):
                strong.append(f"shared network indicator: {host}")
            certs_a = {c["sha256"] for c in ra.get("certificate", {}).get("certificates", [])
                       if c.get("sha256") and not c.get("debug_certificate")}
            certs_b = {c["sha256"] for c in rb.get("certificate", {}).get("certificates", [])
                       if c.get("sha256") and not c.get("debug_certificate")}
            for sha in sorted(certs_a & certs_b):
                strong.append(f"same signing certificate: {sha[:16]}")
            pkg_a, pkg_b = ra.get("info", {}).get("package"), rb.get("info", {}).get("package")
            if pkg_a and pkg_a == pkg_b:
                strong.append(f"same package name: {pkg_a}")

            techniques = ({t["technique_id"] for t in ra.get("mitre", []) if t.get("confidence") != "low"}
                          & {t["technique_id"] for t in rb.get("mitre", []) if t.get("confidence") != "low"})
            if techniques:
                weak.append("common MITRE techniques: " + ", ".join(sorted(techniques)))
            evasion = set(_evasion(ra)) & set(_evasion(rb)) - {"reflection"}
            if evasion:
                weak.append("common evasion indicators: " + ", ".join(sorted(evasion)))
            sensitive = ({p["name"].replace("android.permission.", "") for p in ra.get("permissions", []) if p.get("dangerous")}
                         & {p["name"].replace("android.permission.", "") for p in rb.get("permissions", []) if p.get("dangerous")})
            if sensitive:
                weak.append("common sensitive permissions: " + ", ".join(sorted(sensitive)))
            libs = ({l["name"] for l in ra.get("libraries", [])} & {l["name"] for l in rb.get("libraries", [])})
            if libs:
                weak.append("common libraries: " + ", ".join(sorted(libs)))

            verdict = "strong link" if strong else ("weak similarity" if weak else "no overlap")
            out.append({"a": a["label"], "b": b["label"], "verdict": verdict, "strong": strong, "weak": weak,
                        "note": "Weak similarities alone are not evidence of a shared origin."})
    return sorted(out, key=lambda p: (p["verdict"] != "strong link", p["verdict"] != "weak similarity"))
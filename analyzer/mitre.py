"""Map findings to MITRE ATT&CK for Mobile techniques.
 
A mapping means "this behaviour or capability matches the technique", not
"this technique was proven to be used". Confidence follows the strength of
the evidence behind each finding.
"""
 
BASE_URL = "https://attack.mitre.org/techniques/"
 
# technique id -> (name, tactic)
TECHNIQUES = {
    "T1407": ("Download New Code at Runtime", "Defense Evasion"),
    "T1406": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1623.001": ("Command and Scripting Interpreter: Unix Shell", "Execution"),
    "T1633.001": ("Virtualization/Sandbox Evasion: System Checks", "Defense Evasion"),
    "T1575": ("Native API", "Execution"),
    "T1437.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1544": ("Ingress Tool Transfer", "Command and Control"),
    "T1636.004": ("Protected User Data: SMS Messages", "Collection"),
    "T1636.003": ("Protected User Data: Contact List", "Collection"),
    "T1636.002": ("Protected User Data: Call Log", "Collection"),
    "T1582": ("SMS Control", "Impact"),
    "T1429": ("Audio Capture", "Collection"),
    "T1512": ("Video Capture", "Collection"),
    "T1430": ("Location Tracking", "Collection"),
    "T1453": ("Abuse Accessibility Features", "Credential Access"),
    "T1626.001": ("Abuse Elevation Control Mechanism: Device Administrator Permissions",
                  "Privilege Escalation"),
    "T1417.002": ("Input Capture: GUI Input Capture", "Credential Access"),
    "T1624.001": ("Event Triggered Execution: Broadcast Receivers", "Persistence"),
}
 
# evasion indicator id -> technique ids
INDICATOR_MAP = {
    "dynamic_code_loading": ["T1407"],
    "shell_execution": ["T1623.001"],
    "anti_debugging": ["T1633.001"],
    "emulator_detection": ["T1633.001"],
    "hooking_framework_detection": ["T1633.001"],
    "name_obfuscation": ["T1406"],
    "encrypted_or_hidden_payload": ["T1406"],
    "native_code_loading": ["T1575"],
}
 
# permission -> technique ids
PERMISSION_MAP = {
    "android.permission.READ_SMS": ["T1636.004"],
    "android.permission.RECEIVE_SMS": ["T1636.004"],
    "android.permission.SEND_SMS": ["T1582"],
    "android.permission.READ_CONTACTS": ["T1636.003"],
    "android.permission.READ_CALL_LOG": ["T1636.002"],
    "android.permission.RECORD_AUDIO": ["T1429"],
    "android.permission.CAMERA": ["T1512"],
    "android.permission.ACCESS_FINE_LOCATION": ["T1430"],
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ["T1453"],
    "android.permission.BIND_DEVICE_ADMIN": ["T1626.001"],
    "android.permission.SYSTEM_ALERT_WINDOW": ["T1417.002"],
    "android.permission.REQUEST_INSTALL_PACKAGES": ["T1544"],
    "android.permission.RECEIVE_BOOT_COMPLETED": ["T1624.001"],
}
 
# permissions that are normal in many apps get "low" confidence
COMMON = {
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.SYSTEM_ALERT_WINDOW",
}
 
 
def _url(tid):
    return BASE_URL + tid.replace(".", "/") + "/"
 
 
def map_to_mitre(result):
    found = {}
 
    def add(tid, source, evidence, confidence):
        name, tactic = TECHNIQUES[tid]
        entry = found.setdefault(tid, {
            "technique_id": tid, "name": name, "tactic": tactic,
            "url": _url(tid), "confidence": confidence, "sources": [], "evidence": [],
        })
        order = {"low": 0, "medium": 1, "high": 2}
        if order[confidence] > order[entry["confidence"]]:
            entry["confidence"] = confidence
        if source not in entry["sources"]:
            entry["sources"].append(source)
        for e in evidence:
            if e not in entry["evidence"]:
                entry["evidence"].append(e)
 
    for f in result.get("evasion", []):
        if f["severity"] == "info":
            continue
        for tid in INDICATOR_MAP.get(f["indicator"], []):
            add(tid, f"evasion:{f['indicator']}", f.get("evidence", []), f["severity"])
 
    for p in result.get("permissions", []):
        for tid in PERMISSION_MAP.get(p["name"], []):
            conf = "low" if p["name"] in COMMON else "medium"
            add(tid, "permission", [p["name"].replace("android.permission.", "")], conf)
 
    iocs = result.get("iocs", {})
    if iocs.get("urls") or iocs.get("ips"):
        add("T1437.001", "network_iocs", (iocs.get("urls", []) + iocs.get("ips", []))[:5], "medium")
 
    return sorted(found.values(), key=lambda x: (x["tactic"], x["technique_id"]))
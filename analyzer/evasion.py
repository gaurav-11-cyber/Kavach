"""Evasion and obfuscation indicators found in DEX code and APK assets."""
import math
import re
 
# (indicator id, category, severity, byte pattern, description, min distinct hits)
# If fewer than min hits are found, severity drops to "low": one stray string
# is common in legitimate apps and libraries.
STRING_RULES = [
    ("dynamic_code_loading", "dynamic_loading", "medium",
     rb"DexClassLoader|InMemoryDexClassLoader|PathClassLoader",
     "Loads additional code at runtime", 1),
    ("reflection", "dynamic_loading", "info",
     rb"Ljava/lang/reflect/Method;|Ljava/lang/Class;->forName",
     "Uses reflection (very common, informational only)", 1),
    ("shell_execution", "execution", "medium",
     rb"Ljava/lang/Runtime;->exec|Ljava/lang/ProcessBuilder;",
     "Executes shell commands", 1),
    ("anti_debugging", "anti_analysis", "high",
     rb"isDebuggerConnected|waitingForDebugger|TracerPid",
     "Checks whether a debugger is attached", 2),
    ("emulator_detection", "anti_analysis", "high",
     rb"goldfish|ranchu|sdk_gphone|Genymotion|vbox86|qemu|generic_x86",
     "Looks for several emulator fingerprints", 3),
    ("hooking_framework_detection", "anti_analysis", "medium",
     rb"frida|xposed|substrate|magisk",
     "Looks for several hooking or root frameworks", 3),
    ("root_detection", "anti_analysis", "low",
     rb"/system/bin/su|/system/xbin/su|com\.topjohnwu\.magisk",
     "Checks for root access", 1),
    ("native_code_loading", "dynamic_loading", "info",
     rb"Ljava/lang/System;->loadLibrary|Ljava/lang/System;->load",
     "Loads native libraries (informational)", 1),
    ("string_encoding", "obfuscation", "info",
     rb"Landroid/util/Base64;->decode",
     "Decodes Base64 data at runtime (informational)", 1),
]
 
SHORT_CLASS_RE = re.compile(rb"L(?:[a-zA-Z]{1,2}/){1,3}[a-zA-Z]{1,2};")
ALL_CLASS_RE = re.compile(rb"L[\w/$]{1,120};")
 
# File types that legitimately have high entropy
SAFE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".ogg", ".mp3", ".mp4",
    ".m4a", ".wav", ".ttf", ".otf", ".woff", ".woff2", ".zip", ".gz",
    ".kotlin_module", ".version", ".properties", ".xml", ".json", ".txt",
    ".prof", ".profm", ".dm", ".arsc",
)
 
 
def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)
 
 
def _scan_strings(dex_blobs):
    findings = []
    for ind, category, severity, pattern, desc, min_hits in STRING_RULES:
        rx = re.compile(pattern, re.IGNORECASE)
        hits = set()
        for dex in dex_blobs:
            for m in rx.findall(dex):
                hits.add(m.decode("utf-8", "ignore").lower())
        if hits:
            if len(hits) < min_hits and severity != "info":
                severity = "low"
            findings.append({
                "indicator": ind, "category": category, "severity": severity,
                "description": desc, "evidence": sorted(hits)[:10],
            })
    return findings
 
 
def _scan_obfuscation(dex_blobs):
    short = total = 0
    for dex in dex_blobs:
        short += len(SHORT_CLASS_RE.findall(dex))
        total += len(ALL_CLASS_RE.findall(dex))
    ratio = short / total if total else 0
    if total >= 100 and ratio > 0.25:
        return [{
            "indicator": "name_obfuscation", "category": "obfuscation",
            "severity": "medium",
            "description": "Many classes have very short names (minified or obfuscated)",
            "evidence": [f"{short} of {total} class names are 1-2 characters ({ratio:.0%})"],
        }]
    return []
 
 
def _scan_assets(apk):
    findings = []
    suspicious = []
    for name in apk.get_files():
        lower = name.lower()
        if not (lower.startswith("assets/") or lower.startswith("res/raw/")):
            continue
        if lower.endswith(SAFE_EXTENSIONS) or lower.startswith("assets/dexopt/"):
            continue
        try:
            data = apk.get_file(name)
        except Exception:
            continue
        if len(data) >= 10_000 and _entropy(data) > 7.5:
            suspicious.append(f"{name} ({len(data)} bytes, entropy {_entropy(data):.2f})")
        elif data[:4] in (b"dex\n", b"PK\x03\x04") and len(data) > 1000:
            suspicious.append(f"{name} (embedded {'DEX' if data[:3] == b'dex' else 'archive'})")
    if suspicious:
        findings.append({
            "indicator": "encrypted_or_hidden_payload", "category": "obfuscation",
            "severity": "high",
            "description": "High-entropy or embedded files in assets, possible hidden payload",
            "evidence": suspicious[:10],
        })
    return findings
 
 
def detect_evasion(apk):
    dex_blobs = list(apk.get_all_dex())
    return (
        _scan_strings(dex_blobs)
        + _scan_obfuscation(dex_blobs)
        + _scan_assets(apk)
    )
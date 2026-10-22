"""Generate a YARA rule from an analysis result.

The rule targets the DEX code of an APK, because the APK itself is a
compressed zip and string matching on it does not work. To scan an APK:
    unzip -p app.apk classes.dex > classes.dex && yara rule.yar classes.dex
A rule is only produced when there is something distinctive to match:
network IoCs, or several anti-analysis / loader behaviours together.
"""
import re
from datetime import datetime, timezone
from typing import Optional

DEX_MAGIC = "0x0A786564"  # "dex\n"
BEHAVIOUR_INDICATORS = {
    "dynamic_code_loading", "emulator_detection", "anti_debugging",
    "shell_execution", "hooking_framework_detection",
}


def _yara_string(text):
    """Escape text for use inside a YARA string literal (ASCII only)."""
    text = text.encode("ascii", "ignore").decode()
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _rule_name(package, sha256):
    safe = re.sub(r"[^A-Za-z0-9_]", "_", package or "apk")
    return f"APKScope_{safe}_{sha256[:8]}"


def generate_yara(result, sha256) -> Optional[str]:
    iocs = result.get("iocs", {})
    ioc_strings = list(dict.fromkeys(iocs.get("urls", []) + iocs.get("ips", [])))[:15]

    behaviour_strings = []
    for f in result.get("evasion", []):
        if f["indicator"] in BEHAVIOUR_INDICATORS and f["severity"] in ("medium", "high"):
            behaviour_strings += f.get("evidence", [])
    behaviour_strings = list(dict.fromkeys(behaviour_strings))[:10]

    use_behaviour = len(behaviour_strings) >= 3
    if not ioc_strings and not use_behaviour:
        return None

    info = result.get("info", {})
    risk = result.get("risk", {})
    techniques = ",".join(t["technique_id"] for t in result.get("mitre", []))
    lines = [
        f"rule {_rule_name(info.get('package'), sha256)}",
        "{",
        "    meta:",
        '        author = "APKScope"',
        f'        description = "Indicators from {_yara_string(info.get("package") or "unknown")}"',
        f'        sample_sha256 = "{sha256}"',
        f'        risk_score = "{risk.get("score", 0)} ({risk.get("level", "n/a")})"',
        f'        mitre = "{techniques}"',
        f'        date = "{datetime.now(timezone.utc).date()}"',
        '        usage = "scan classes.dex extracted from the APK"',
        "    strings:",
    ]
    for i, s in enumerate(ioc_strings, 1):
        lines.append(f'        $ioc{i} = "{_yara_string(s)}" ascii')
    for i, s in enumerate(behaviour_strings, 1):
        lines.append(f'        $b{i} = "{_yara_string(s)}" ascii nocase')

    clauses = []
    if ioc_strings:
        clauses.append("any of ($ioc*)")
    if use_behaviour:
        clauses.append(f"{min(3, len(behaviour_strings))} of ($b*)")
    lines += [
        "    condition:",
        f"        uint32(0) == {DEX_MAGIC} and (" + " or ".join(clauses) + ")",
        "}",
    ]
    return "\n".join(lines) + "\n"

"""CLI entry point: python analyze.py path/to/app.apk"""
from loguru import logger
logger.remove()  # silence androguard debug logs

import argparse
import json
import os
from typing import Any

from analyzer.manifest import (
    load_apk, get_basic_info, get_permissions, get_components,
)
from analyzer.iocs import extract_iocs
from analyzer.capabilities import detect_capabilities
from analyzer.certificate import analyze_certificates
from analyzer.evasion import detect_evasion
from analyzer.libraries import detect_libraries
from analyzer.scoring import score_apk
from analyzer.correlate import correlate_findings
from analyzer.mitre import map_to_mitre


def analyze(path: str) -> dict[str, Any]:
    apk = load_apk(path)
    result = {
        "info": get_basic_info(apk),
        "permissions": get_permissions(apk),
        "components": get_components(apk),
        "iocs": extract_iocs(apk),
        "certificate": analyze_certificates(apk),
        "evasion": detect_evasion(apk),
        "libraries": detect_libraries(apk),
    }
    result["capabilities"] = detect_capabilities(apk, result)
    result["risk"] = score_apk(result)
    result["mitre"] = map_to_mitre(result)
    result["correlations"] = correlate_findings(result)
    return result


def print_summary(results):
    """Compact table: one row per APK."""
    print(f"{'APK':40} {'SCORE':>5}  {'LEVEL':8} TOP FINDINGS")
    for name, r in results.items():
        top = ", ".join(x["rule"] for x in r["risk"]["breakdown"][:3]) or "-"
        print(f"{os.path.basename(name)[:40]:40} {r['risk']['score']:>5}  "
              f"{r['risk']['level']:8} {top}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static APK analyzer")
    parser.add_argument("apks", nargs="+", help="path(s) to APK file(s)")
    parser.add_argument("--summary", action="store_true",
                        help="print one summary row per APK instead of full JSON")
    args = parser.parse_args()

    results = {path: analyze(path) for path in args.apks}
    if args.summary:
        print_summary(results)
    elif len(results) == 1:
        print(json.dumps(next(iter(results.values())), indent=2))
    else:
        print(json.dumps(results, indent=2))
"""CLI entry point: python analyze.py path/to/app.apk"""
import argparse
import json

from analyzer.manifest import (
    load_apk, get_basic_info, get_permissions, get_components,
)


def analyze(path):
    apk = load_apk(path)
    return {
        "info": get_basic_info(apk),
        "permissions": get_permissions(apk),
        "components": get_components(apk),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Static APK analyzer")
    parser.add_argument("apk", help="path to APK file")
    args = parser.parse_args()
    print(json.dumps(analyze(args.apk), indent=2))

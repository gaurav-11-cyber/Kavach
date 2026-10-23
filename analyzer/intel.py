"""Threat-intelligence lookups by file hash (VirusTotal and MalwareBazaar).

Only the SHA-256 hash is sent. The APK itself is never uploaded.
API keys are read from the environment or a local .env file:
    VT_API_KEY   VirusTotal key (free tier is enough)
    MB_AUTH_KEY  abuse.ch Auth-Key for MalwareBazaar
Run from the command line:  python -m analyzer.intel <sha256>
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional here
    pass

VT_URL = "https://www.virustotal.com/api/v3/files/{}"
MB_URL = "https://mb-api.abuse.ch/api/v1/"
TIMEOUT = 10


def _request(url: str, headers: dict[str, str],
             data: Optional[dict[str, str]] = None) -> tuple[int, Any]:
    """Return (http_status, parsed_json_or_None). Raises URLError on network failure."""
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as err:
        try:
            return err.code, json.loads(err.read().decode("utf-8", "replace"))
        except ValueError:
            return err.code, None


def _result(source: str, status: str, summary: str, link: str = "",
            details: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    return {"source": source, "status": status, "summary": summary,
            "link": link, "details": details or {}}


def lookup_virustotal(sha256: str) -> dict[str, Any]:
    key = os.environ.get("VT_API_KEY", "").strip()
    if not key:
        return _result("VirusTotal", "no_key", "Set VT_API_KEY in .env to enable this lookup.")
    link = f"https://www.virustotal.com/gui/file/{sha256}"
    try:
        code, body = _request(VT_URL.format(sha256), {"x-apikey": key})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return _result("VirusTotal", "error", f"Network error: {exc}")
    if code == 404:
        return _result("VirusTotal", "not_found", "Hash not known to VirusTotal.")
    if code != 200 or not isinstance(body, dict):
        return _result("VirusTotal", "error", f"HTTP {code}")
    attrs = body.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    total = sum(stats.values()) or 0
    malicious = stats.get("malicious", 0)
    family = attrs.get("popular_threat_classification", {}).get("suggested_threat_label")
    summary = f"{malicious}/{total} engines flag it as malicious"
    if family:
        summary += f" (suggested label: {family})"
    return _result("VirusTotal", "found", summary, link, {"stats": stats, "family": family})


def lookup_malwarebazaar(sha256: str) -> dict[str, Any]:
    key = os.environ.get("MB_AUTH_KEY", "").strip()
    if not key:
        return _result("MalwareBazaar", "no_key", "Set MB_AUTH_KEY in .env to enable this lookup.")
    link = f"https://bazaar.abuse.ch/sample/{sha256}/"
    try:
        code, body = _request(MB_URL, {"Auth-Key": key}, {"query": "get_info", "hash": sha256})
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return _result("MalwareBazaar", "error", f"Network error: {exc}")
    if code != 200 or not isinstance(body, dict):
        return _result("MalwareBazaar", "error", f"HTTP {code}")
    status = body.get("query_status")
    if status == "hash_not_found":
        return _result("MalwareBazaar", "not_found", "Hash not in MalwareBazaar.")
    if status != "ok" or not body.get("data"):
        return _result("MalwareBazaar", "error", f"Unexpected response: {status}")
    entry = body["data"][0]
    tags = ", ".join(entry.get("tags") or []) or "none"
    summary = (f"Known sample. Signature: {entry.get('signature') or 'unknown'}; "
               f"tags: {tags}; first seen: {entry.get('first_seen') or 'unknown'}")
    return _result("MalwareBazaar", "found", summary, link,
                   {"signature": entry.get("signature"), "tags": entry.get("tags")})


def lookup_hash(sha256: str) -> list[dict[str, Any]]:
    return [lookup_virustotal(sha256), lookup_malwarebazaar(sha256)]


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m analyzer.intel <sha256>")
    for item in lookup_hash(sys.argv[1]):
        print(f"{item['source']:14} {item['status']:10} {item['summary']}")

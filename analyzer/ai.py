"""AI investigation assistant, grounded in APKScope's own findings.

A local LLM (Ollama) explains the structured findings in plain language and
answers analyst questions. It never changes the risk score. Every answer is
checked: identifiers it mentions (rule names, technique IDs, IPs, hosts,
permissions) must exist in the report, otherwise they are flagged as
unverified. Nothing leaves the machine, because the model runs locally.

Setup:  ollama pull llama3.2:3b     (override with OLLAMA_MODEL)
"""
import json
import os
import re
import urllib.error
import urllib.request
from typing import Any, Optional

HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
TIMEOUT = 180

SYSTEM_PROMPT = (
    "You are a malware triage assistant helping a SOC analyst. You are given a REPORT produced by "
    "a static APK analysis tool.\n"
    "Rules:\n"
    "- Use ONLY facts that appear in the REPORT. Do not invent findings, hosts, IPs or techniques.\n"
    "- Use rule names, technique IDs and indicators exactly as written in the REPORT.\n"
    "- If the REPORT does not contain the answer, say: not in the report.\n"
    "- The APK was not executed. Say 'suggests' or 'fits', never claim proof.\n"
    "- Do NOT guess what a finding could be used for. Do not connect two findings unless the REPORT "
    "itself lists them together under CORRELATED FINDINGS.\n"
    "- Do not mention a capability (for example tracking, stealing, spying) unless the REPORT names it.\n"
    "- Be short and plain. No long introductions."
)
SUMMARY_REQUEST = (
    "Write an investigation summary with exactly three short sections:\n"
    "Why this APK deserves attention:\nKey evidence (name the strongest rules and indicators):\n"
    "What to check next (2-4 concrete steps):"
)
LINKS_REQUEST = (
    "Explain these APK relationships. Say which links are direct (strong) and which are only weak "
    "similarities, and suggest 2-3 follow-up checks. Be short."
)

NEXT_STEPS = {
    "sms_to_network": "Find where SMS content is read in the code and whether it is sent to the listed hosts.",
    "sms_with_internet": "Check what the app does with SMS content and where it can send data.",
    "staged_payload": "Find what code is loaded at runtime and where the loaded file comes from.",
    "takeover_toolkit": "Review how the accessibility service and overlay are used and what screens they target.",
    "evasion_cluster": "Review the anti-analysis checks and what the app does when they trigger.",
    "boot_persistent_loader": "Check what runs at boot and whether it fetches or loads new code.",
    "debug_signed_risky": "Compare the signing certificate with the publisher's official release.",
    "sms_with_network": "Look at SMS read/receive code paths and any outgoing network calls.",
    "accessibility_service": "Review the accessibility service configuration and its event handling.",
    "dynamic_code_loading": "Find the DexClassLoader usage and the file or URL it loads from.",
    "encrypted_or_hidden_payload": "Inspect the flagged asset files and try to identify their format.",
    "external_hosts": "Check the listed hosts against threat-intelligence sources.",
    "hardcoded_public_ips": "Check the listed IP addresses against threat-intelligence sources.",
    "debug_certificate": "Compare the signing certificate with the publisher's official release.",
}
DEFAULT_STEP = "Review the evidence listed for each finding and confirm it in the decompiled code."


class AIError(Exception):
    """The local model could not be reached or gave no answer."""


# ---------------------------------------------------------------- Ollama client
def _http_json(path: str, payload: Optional[dict[str, Any]] = None, timeout: float = TIMEOUT) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(HOST + path, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise AIError(str(exc)) from exc


def ollama_status() -> dict[str, Any]:
    try:
        tags = _http_json("/api/tags", timeout=3)
    except AIError:
        return {"available": False, "model": MODEL,
                "message": "Ollama is not running. Open the Ollama app or run `ollama serve`."}
    names = [m.get("name", "") for m in tags.get("models", [])]
    present = MODEL in names or (":" not in MODEL and any(n.split(":")[0] == MODEL for n in names))
    if not present:
        return {"available": False, "model": MODEL,
                "message": f"Model not installed. Run `ollama pull {MODEL}`."}
    return {"available": True, "model": MODEL, "message": "ready"}


def _chat(messages: list[dict[str, str]]) -> str:
    body = _http_json("/api/chat", {
        "model": MODEL, "messages": messages, "stream": False,
        "options": {"temperature": 0.2, "num_ctx": 4096, "num_predict": 450}})
    text = (body.get("message", {}).get("content") or "").strip()
    if not text:
        raise AIError("The model returned an empty answer.")
    return text


# ---------------------------------------------------------------- grounded context
def build_context(result: dict[str, Any], correlations: list[dict[str, Any]]) -> str:
    info, risk = result.get("info", {}), result.get("risk", {})
    lines = [f"PACKAGE: {info.get('package')}  VERSION: {info.get('version')}",
             f"RISK SCORE: {risk.get('score')}/100 ({risk.get('level')})", "SCORE BREAKDOWN:"]
    for b in risk.get("breakdown", []):
        ev = ", ".join(str(e) for e in b["evidence"][:3])
        lines.append(f"- {b['rule']} (+{b['points']}): {b['reason']}" + (f" | evidence: {ev}" if ev else ""))
    if not risk.get("breakdown"):
        lines.append("- no risk indicators triggered")
    lines.append("MITRE TECHNIQUES:")
    for t in result.get("mitre", []):
        lines.append(f"- {t['technique_id']} {t['name']} (confidence: {t['confidence']})")
    lines.append("CORRELATED FINDINGS:")
    for c in correlations:
        lines.append(f"- {c['id']} [{c['severity']}] {c['title']}: {c['why']} | evidence: "
                     + ", ".join(c["evidence"]))
    if not correlations:
        lines.append("- none")
    iocs = result.get("iocs", {})
    lines.append("NETWORK IOCS: " + (", ".join(iocs.get("urls", [])[:5] + iocs.get("ips", [])[:5]) or "none"))
    lines.append("EVASION: " + (", ".join(f"{e['indicator']} ({e['severity']})"
                                          for e in result.get("evasion", [])) or "none"))
    certs = result.get("certificate", {}).get("certificates", [])
    lines.append("CERTIFICATE: " + (", ".join(
        f"debug={c.get('debug_certificate')} self_signed={c.get('self_signed')} expired={c.get('expired')}"
        for c in certs) or "none found"))
    return "\n".join(lines)


def build_links_context(pairs: list[dict[str, Any]]) -> str:
    lines = []
    for p in pairs[:10]:
        lines.append(f"PAIR {p['a']} <-> {p['b']}: {p['verdict']}")
        lines += [f"  strong: {s}" for s in p["strong"]] + [f"  weak: {w}" for w in p["weak"]]
    return "\n".join(lines) or "no pairs"


# ---------------------------------------------------------------- grounding check
_TLDS = "com|net|org|ru|cn|io|info|xyz|top|tk|ml|ga|cf|gq|site|online|club|cc|pw|shop|live|vip|in"
_TECH_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SNAKE_RE = re.compile(r"\b[a-z][a-z0-9]*(?:_[a-z0-9]+)+\b")
_PERM_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")
_HOST_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:" + _TLDS + r")\b")
_SCORE_RE = re.compile(r"score(?: of| is|:)?\s*(\d{1,3})\b", re.I)


def report_tokens(result: dict[str, Any], correlations: list[dict[str, Any]]) -> set[str]:
    known: set[str] = set()
    for b in result.get("risk", {}).get("breakdown", []):
        known |= {b["rule"], b["group"]}
        known |= {str(e) for e in b["evidence"]}
    for e in result.get("evasion", []):
        known |= {e["indicator"], e["category"] if "category" in e else ""}
        known |= {str(x) for x in e.get("evidence", [])}
    for t in result.get("mitre", []):
        known |= {t["technique_id"]} | {str(x) for x in t["evidence"]}
    for p in result.get("permissions", []):
        known.add(p["name"].replace("android.permission.", ""))
    for c in correlations:
        known |= {c["id"]} | set(c["evidence"]) | set(c["mitre"])
    iocs = result.get("iocs", {})
    for key in ("urls", "ips", "domains"):
        known |= set(iocs.get(key, []))
    for url in iocs.get("urls", []):
        host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
        known.add(host)
    known.add(str(result.get("info", {}).get("package")))
    return {k.lower() for k in known if k}


def check_grounding(answer: str, known: set[str], score: Optional[int] = None) -> list[str]:
    """Return identifiers in the answer that do not appear in the report."""
    candidates = set(_TECH_RE.findall(answer)) | set(_IP_RE.findall(answer))
    candidates |= set(_SNAKE_RE.findall(answer)) | set(_PERM_RE.findall(answer))
    candidates |= set(_HOST_RE.findall(answer.lower()))
    unverified = {c for c in candidates if c.lower() not in known}
    # an IP is also a "host" shape, and package names look like hosts: skip fragments of known items
    unverified = {c for c in unverified if not any(c.lower() in k for k in known if len(k) > len(c))}
    if score is not None:
        for number in _SCORE_RE.findall(answer):
            if int(number) != score:
                unverified.add(f"score {number}")
    return sorted(unverified)


# ---------------------------------------------------------------- outputs
def template_summary(result: dict[str, Any], correlations: list[dict[str, Any]]) -> str:
    risk = result.get("risk", {})
    top = risk.get("breakdown", [])[:3]
    parts = [f"Risk score {risk.get('score')}/100 ({risk.get('level')}).", "", "Why this APK deserves attention:"]
    parts += [f"- {b['rule']}: {b['reason']}" for b in top] or ["- No risk indicators were triggered."]
    if correlations:
        parts += ["", "Related findings:"] + [f"- {c['title']}: {c['why']}" for c in correlations[:3]]
    steps = []
    for key in [c["id"] for c in correlations] + [b["rule"] for b in top]:
        step = NEXT_STEPS.get(key)
        if step and step not in steps:
            steps.append(step)
    parts += ["", "What to check next:"] + [f"- {s}" for s in (steps[:4] or [DEFAULT_STEP])]
    return "\n".join(parts)


def summarize(result: dict[str, Any], correlations: list[dict[str, Any]]) -> dict[str, Any]:
    status = ollama_status()
    if status["available"]:
        try:
            text = _chat([
                {"role": "system", "content": SYSTEM_PROMPT + "\n\nREPORT:\n" + build_context(result, correlations)},
                {"role": "user", "content": SUMMARY_REQUEST}])
            known = report_tokens(result, correlations)
            return {"text": text, "source": "ai", "model": MODEL, "note": "",
                    "unverified": check_grounding(text, known, result.get("risk", {}).get("score"))}
        except AIError as exc:
            status = {"message": f"AI request failed: {exc}"}
    return {"text": template_summary(result, correlations), "source": "template", "model": None,
            "note": status["message"], "unverified": []}


def ask(result: dict[str, Any], correlations: list[dict[str, Any]], question: str,
        history: Optional[list[dict[str, str]]] = None) -> dict[str, Any]:
    """Answer an analyst question from the report. Raises AIError if the model is unavailable."""
    messages = [{"role": "system", "content": SYSTEM_PROMPT + "\n\nREPORT:\n" + build_context(result, correlations)}]
    messages += [{"role": m["role"], "content": m["content"]} for m in (history or [])[-6:]]
    messages.append({"role": "user", "content": question})
    text = _chat(messages)
    known = report_tokens(result, correlations)
    return {"text": text, "unverified": check_grounding(text, known, result.get("risk", {}).get("score"))}


def explain_links(pairs: list[dict[str, Any]]) -> dict[str, Any]:
    context = build_links_context(pairs)
    text = _chat([{"role": "system", "content": SYSTEM_PROMPT + "\n\nREPORT:\n" + context},
                  {"role": "user", "content": LINKS_REQUEST}])
    known = {w.lower() for p in pairs for s in p["strong"] + p["weak"] for w in re.split(r"[:,]\s*", s)}
    known |= {p["a"].lower() for p in pairs} | {p["b"].lower() for p in pairs}
    return {"text": text, "unverified": check_grounding(text, known)}
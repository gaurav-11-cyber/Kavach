"""Relationship graph between analysed APKs and the artifacts they share."""
from urllib.parse import urlparse

LEVEL_COLORS = {
    "LOW": "#c8e6c9", "MEDIUM": "#fff59d", "HIGH": "#ffcc80", "CRITICAL": "#ef9a9a",
}
KIND_STYLE = {  # kind -> (shape, fill color)
    "IoCs": ("ellipse", "#bbdefb"),
    "Libraries": ("box", "#e1bee7"),
    "MITRE techniques": ("hexagon", "#ffe0b2"),
    "Permissions": ("note", "#f5f5f5"),
}
ALL_KINDS = list(KIND_STYLE)


def _esc(text):
    return str(text).replace("\\", "/").replace('"', "'")


def artifacts_of(result, include_low=False):
    """Return {kind: set(names)} for one analysis result."""
    iocs = result.get("iocs", {})
    hosts = {urlparse(u).hostname for u in iocs.get("urls", []) if urlparse(u).hostname}
    return {
        "IoCs": hosts | set(iocs.get("ips", [])),
        "Libraries": {l["name"] for l in result.get("libraries", [])},
        "MITRE techniques": {
            t["technique_id"] for t in result.get("mitre", [])
            if include_low or t.get("confidence") != "low"
        },
        "Permissions": {
            p["name"].replace("android.permission.", "")
            for p in result.get("permissions", []) if p.get("dangerous")
        },
    }


def build_dot(items, kinds, only_shared=True, include_low=False):
    """items: list of {"label", "score", "level", "result"}. Returns (dot, artifact_count)."""
    per_apk = [(it, artifacts_of(it["result"], include_low)) for it in items]

    # which APKs use each artifact
    users = {}
    for idx, (_, arts) in enumerate(per_apk):
        for kind in kinds:
            for name in arts.get(kind, ()):
                users.setdefault((kind, name), []).append(idx)

    chosen = {k: v for k, v in users.items() if not only_shared or len(v) >= 2}

    lines = ["graph G {", "rankdir=LR;", "nodesep=0.3;", "ranksep=1.1;",
             'node [fontname="Helvetica", fontsize=10];']
    for idx, (it, _) in enumerate(per_apk):
        color = LEVEL_COLORS.get(it["level"], "#ffffff")
        lines.append(
            f'a{idx} [label="{_esc(it["label"])}\\nscore {it["score"]} ({it["level"]})", '
            f'shape=box, style="filled,bold", fillcolor="{color}"];'
        )
    for n, ((kind, name), idxs) in enumerate(chosen.items()):
        shape, fill = KIND_STYLE[kind]
        lines.append(f'n{n} [label="{_esc(name)}", shape={shape}, style=filled, fillcolor="{fill}"];')
        for idx in idxs:
            lines.append(f"a{idx} -- n{n};")
    lines.append("}")
    return "\n".join(lines), len(chosen)
"""PDF forensic report for one analysed APK."""
import textwrap
from datetime import datetime, timezone
from io import BytesIO
from typing import Any, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, Preformatted, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

from analyzer.yara_gen import generate_yara

LEVEL_COLORS = {"LOW": "#2e7d32", "MEDIUM": "#f9a825", "HIGH": "#ef6c00", "CRITICAL": "#c62828"}
PAGE_WIDTH = A4[0] - 30 * mm  # usable width with 15 mm margins
MAX_LIST = 30

_styles = getSampleStyleSheet()
BODY = ParagraphStyle("body", parent=_styles["BodyText"], fontSize=8.5, leading=11)
CELL = ParagraphStyle("cell", parent=BODY, fontSize=7.5, leading=9.5)
HEAD = ParagraphStyle("head", parent=CELL, fontName="Helvetica-Bold", textColor=colors.white)
H2 = ParagraphStyle("h2", parent=_styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
SMALL = ParagraphStyle("small", parent=BODY, fontSize=7.5, textColor=colors.grey)


def _t(value: Any) -> str:
    """Make text safe for the PDF core fonts (Latin-1) and for ReportLab markup."""
    text = str(value).encode("latin-1", "replace").decode("latin-1")
    return escape(text)


def _table(header: list[str], rows: list[list[Any]], widths_mm: list[float]) -> Table:
    data = [[Paragraph(_t(h), HEAD) for h in header]]
    data += [[Paragraph(_t(c).replace("\n", "<br/>"), CELL) for c in row] for row in rows]
    table = Table(data, colWidths=[w * mm for w in widths_mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#37474f")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#b0bec5")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f7f8")]),
    ]))
    return table


def _join(items: list[Any], limit: int = 5) -> str:
    shown = [str(i) for i in items[:limit]]
    extra = len(items) - limit
    return ", ".join(shown) + (f" (+{extra} more)" if extra > 0 else "")


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.grey)
    canvas.drawString(15 * mm, 8 * mm, "APKScope static analysis report")
    canvas.drawRightString(A4[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(filename: str, sha256: str, result: dict[str, Any],
              intel: Optional[list[dict[str, Any]]] = None) -> bytes:
    risk = result["risk"]
    info = result.get("info", {})
    story: list[Any] = []

    # ---- header ----
    story.append(Paragraph("APKScope Forensic Report", _styles["Title"]))
    story.append(Paragraph(f"<b>File:</b> {_t(filename)}", BODY))
    story.append(Paragraph(f"<b>SHA-256:</b> {_t(sha256)}", BODY))
    story.append(Paragraph(
        f"<b>Package:</b> {_t(info.get('package'))} &nbsp; <b>Version:</b> {_t(info.get('version'))}"
        f" &nbsp; <b>Min/Target SDK:</b> {_t(info.get('min_sdk'))}/{_t(info.get('target_sdk'))}", BODY))
    story.append(Paragraph(
        f"<b>Generated:</b> {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", BODY))
    color = LEVEL_COLORS.get(risk["level"], "#000000")
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        f'<font size="16" color="{color}"><b>Risk score {risk["score"]} / 100 - {risk["level"]}</b></font>', BODY))

    # ---- risk breakdown ----
    story.append(Paragraph("Why this score", H2))
    if risk["breakdown"]:
        story.append(_table(
            ["Rule", "Points", "Reason", "Evidence"],
            [[b["rule"], b["points"], b["reason"], _join(b["evidence"], 4)] for b in risk["breakdown"]],
            [34, 14, 70, 62]))
    else:
        story.append(Paragraph("No risk indicators were triggered.", BODY))

    # ---- MITRE ----
    story.append(Paragraph("MITRE ATT&amp;CK for Mobile", H2))
    techniques = result.get("mitre", [])
    if techniques:
        story.append(_table(
            ["ID", "Technique", "Tactic", "Confidence", "Evidence"],
            [[t["technique_id"], t["name"], t["tactic"], t["confidence"], _join(t["evidence"], 3)]
             for t in techniques],
            [20, 58, 30, 20, 52]))
        story.append(Paragraph(
            "A mapping means the behaviour or capability matches the technique. "
            "It does not prove the technique was used.", SMALL))
    else:
        story.append(Paragraph("No techniques mapped.", BODY))

    # ---- IoCs ----
    story.append(Paragraph("Indicators of compromise", H2))
    iocs = result.get("iocs", {})
    rows = []
    for key in ("urls", "ips", "domains"):
        values = iocs.get(key, [])
        text = "\n".join(values[:MAX_LIST])
        if len(values) > MAX_LIST:
            text += f"\n(+{len(values) - MAX_LIST} more)"
        rows.append([key, len(values), text or "-"])
    story.append(_table(["Type", "Count", "Values"], rows, [20, 14, 146]))
    story.append(Paragraph("Bare domain strings are low confidence and are not scored.", SMALL))

    # ---- evasion ----
    story.append(Paragraph("Evasion and obfuscation indicators", H2))
    if result.get("evasion"):
        story.append(_table(
            ["Indicator", "Severity", "Description", "Evidence"],
            [[e["indicator"], e["severity"], e["description"], _join(e["evidence"], 4)]
             for e in result["evasion"]],
            [38, 16, 70, 56]))
    else:
        story.append(Paragraph("None found.", BODY))

    # ---- certificate ----
    story.append(Paragraph("Signing certificate", H2))
    cert = result.get("certificate", {})
    story.append(Paragraph(
        f"Signing schemes: v1={cert.get('signed_v1')}, v2={cert.get('signed_v2')}, v3={cert.get('signed_v3')}", BODY))
    for c in cert.get("certificates", []):
        story.append(_table(["Field", "Value"], [
            ["Subject", c.get("subject")], ["Issuer", c.get("issuer")],
            ["SHA-256", c.get("sha256")], ["Algorithm", c.get("signature_algorithm")],
            ["Valid", f"{c.get('not_before')} to {c.get('not_after')}"],
            ["Self-signed / debug / expired",
             f"{c.get('self_signed')} / {c.get('debug_certificate')} / {c.get('expired')}"],
        ], [40, 140]))

    # ---- permissions and components ----
    perms = result.get("permissions", [])
    sensitive = [p["name"].replace("android.permission.", "") for p in perms if p.get("dangerous")]
    story.append(Paragraph("Permissions and exposed components", H2))
    story.append(Paragraph(
        f"{len(perms)} permissions requested, {len(sensitive)} flagged sensitive: "
        f"{_t(', '.join(sensitive) or 'none')}", BODY))
    exposed = [c["name"] for c in result.get("components", [])
               if c["exported"] and not c["permission"] and c["type"] != "activity"]
    story.append(Paragraph(
        f"Exported services, receivers or providers without a protecting permission: "
        f"{_t(', '.join(exposed) or 'none')}", BODY))

    # ---- libraries ----
    libs = result.get("libraries", [])
    if libs:
        story.append(Paragraph("Third-party libraries", H2))
        story.append(_table(["Library", "Category", "Package", "Classes"],
                            [[l.get("name"), l.get("category"), l.get("package", "-"), l.get("classes", "-")] for l in libs],
                            [50, 30, 80, 20]))

    # ---- threat intel ----
    if intel:
        story.append(Paragraph("Threat intelligence (hash lookup)", H2))
        story.append(_table(["Source", "Status", "Summary"],
                            [[i["source"], i["status"], i["summary"]] for i in intel], [34, 24, 122]))

    # ---- YARA ----
    story.append(Paragraph("YARA rule", H2))
    rule = generate_yara(result, sha256)
    if rule is None:
        story.append(Paragraph("No distinctive indicators found, so no rule was generated.", BODY))
    else:
        wrapped = "\n".join(
            wrapped_line for line in rule.splitlines()
            for wrapped_line in (textwrap.wrap(line, 100, subsequent_indent="        ",
                                               break_long_words=True) or [""]))
        story.append(Preformatted(wrapped.encode("latin-1", "replace").decode("latin-1"),
                                  ParagraphStyle("code", fontName="Courier", fontSize=6.5, leading=8)))

    # ---- disclaimer ----
    story.append(Spacer(1, 10))
    story.append(Paragraph(
        "This report comes from static analysis only. The APK was not executed. Scores come from "
        "transparent rules and are meant for triage, not as a verdict.", SMALL))

    buffer = BytesIO()
    SimpleDocTemplate(buffer, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm,
                      topMargin=15 * mm, bottomMargin=15 * mm,
                      title=f"APKScope report - {filename}", author="APKScope"
                      ).build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()

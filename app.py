"""APKScope dashboard. Run with: streamlit run app.py"""
import hashlib
import os
import tempfile
 
import pandas as pd
import streamlit as st
 
from analyze import analyze
from analyzer import storage
from analyzer.graph import ALL_KINDS, build_dot
from analyzer.yara_gen import generate_yara
 
st.set_page_config(page_title="APKScope", layout="wide")
st.title("APKScope")
st.caption("Android APK triage: static analysis, explainable risk score, MITRE ATT&CK mapping")
 
# ---------- sidebar: upload and analyze ----------
with st.sidebar:
    st.header("Analyze")
    files = st.file_uploader("Upload APK file(s)", type=["apk"], accept_multiple_files=True)
    if st.button("Analyze", disabled=not files, type="primary"):
        for f in files:
            data = f.getvalue()
            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                tmp.write(data)
                path = tmp.name
            try:
                with st.spinner(f"Analyzing {f.name}..."):
                    result = analyze(path)
                storage.save_result(f.name, hashlib.sha256(data).hexdigest(), result)
                st.success(f"{f.name}: score {result['risk']['score']} ({result['risk']['level']})")
            except Exception as exc:  # corrupt or unsupported APK
                st.error(f"{f.name}: could not analyze ({exc})")
            finally:
                os.unlink(path)
 
rows = storage.list_results()
tab_report, tab_compare, tab_graph = st.tabs(["Report", "Compare", "Relationships"])
 
# ---------- report tab ----------
with tab_report:
    if not rows:
        st.info("No analyses yet. Upload an APK in the sidebar and click Analyze.")
    else:
        labels = {r["id"]: f"{r['filename']}  ({r['score']} {r['level']})" for r in rows}
        chosen = st.selectbox("APK", list(labels), format_func=lambda i: labels[i])
        record = storage.get_result(chosen)
        if record is None:
            st.error("This analysis was not found in the database.")
            st.stop()
        res = record["result"]
        risk = res["risk"]
 
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Risk score", f"{risk['score']} / 100")
        c2.metric("Level", risk["level"])
        c3.metric("Package", res["info"].get("package") or "-")
        c4.metric("Version", res["info"].get("version") or "-")
        st.progress(min(risk["score"], 100) / 100)
        st.caption(f"SHA-256: {record['sha256']}")
 
        st.subheader("Why this score")
        if risk["breakdown"]:
            st.dataframe(pd.DataFrame([
                {"rule": b["rule"], "points": b["points"], "group": b["group"],
                 "reason": b["reason"], "evidence": ", ".join(map(str, b["evidence"][:5]))}
                for b in risk["breakdown"]
            ]), width="stretch", hide_index=True)
        else:
            st.write("No risk indicators were triggered.")
 
        st.subheader("MITRE ATT&CK for Mobile")
        show_low = st.checkbox("Include low-confidence techniques", value=False, key="mitre_low")
        techniques = [t for t in res.get("mitre", []) if show_low or t["confidence"] != "low"]
        hidden = len(res.get("mitre", [])) - len(techniques)
        if techniques:
            st.dataframe(pd.DataFrame([
                {"technique": t["technique_id"], "name": t["name"], "tactic": t["tactic"],
                 "confidence": t["confidence"], "evidence": ", ".join(map(str, t["evidence"][:4])),
                 "link": t["url"]}
                for t in techniques
            ]), width="stretch", hide_index=True,
                column_config={"link": st.column_config.LinkColumn("link")})
        else:
            st.write("No medium or high confidence techniques mapped.")
        if hidden and not show_low:
            st.caption(f"{hidden} low-confidence technique(s) hidden.")
 
        left, right = st.columns(2)
        with left:
            with st.expander("Indicators of compromise", expanded=True):
                for key in ("urls", "ips", "domains"):
                    vals = res["iocs"].get(key, [])
                    st.markdown(f"**{key}** ({len(vals)})")
                    if vals:
                        st.code("\n".join(vals))
            with st.expander("Evasion indicators"):
                if res["evasion"]:
                    st.dataframe(pd.DataFrame([
                        {"indicator": e["indicator"], "severity": e["severity"],
                         "evidence": ", ".join(map(str, e["evidence"][:4]))}
                        for e in res["evasion"]
                    ]), width="stretch", hide_index=True)
                else:
                    st.write("None found.")
        with right:
            with st.expander("Permissions", expanded=True):
                st.dataframe(pd.DataFrame(res["permissions"]), width="stretch",
                             hide_index=True)
            with st.expander("Components"):
                st.dataframe(pd.DataFrame(res["components"]), width="stretch",
                             hide_index=True)
            with st.expander("Signing certificate"):
                st.json(res["certificate"])
            with st.expander("Libraries"):
                st.dataframe(pd.DataFrame(res["libraries"]), width="stretch",
                             hide_index=True)
        with st.expander("YARA rule"):
            rule = generate_yara(res, record["sha256"])
            if rule is None:
                st.write("No distinctive indicators found, so no YARA rule was generated.")
            else:
                st.code(rule, language="text")
                st.download_button("Download rule", rule, file_name=f"{record['filename']}.yar")
                st.caption("Scan the DEX code: unzip -p app.apk classes.dex > classes.dex, "
                           "then run yara on classes.dex.")
        with st.expander("Raw JSON"):
            st.json(res)
 
# ---------- compare tab ----------
with tab_compare:
    if len(rows) < 2:
        st.info("Analyze at least two APKs to compare them.")
    else:
        table = []
        for r in rows:
            rec = storage.get_result(r["id"])
            if rec is None:
                continue
            res = rec["result"]
            table.append({
                "file": r["filename"], "package": r["package"], "score": r["score"],
                "level": r["level"],
                "top findings": ", ".join(b["rule"] for b in res["risk"]["breakdown"][:3]) or "-",
                "techniques": len(res.get("mitre", [])),
                "iocs": sum(len(res["iocs"].get(k, [])) for k in ("urls", "ips")),
            })
        df = pd.DataFrame(table)
        st.bar_chart(df.set_index("file")["score"])
        st.dataframe(df.sort_values("score", ascending=False),
                     width="stretch", hide_index=True)
 
# ---------- relationships tab ----------
with tab_graph:
    st.write("APKs and the indicators, libraries, techniques or permissions they have in common.")
    kinds = st.multiselect("Show", ALL_KINDS, default=["IoCs", "Libraries", "MITRE techniques"])
    only_shared = st.checkbox("Only items shared by 2 or more APKs", value=len(rows) >= 2)
    include_low = st.checkbox("Include low-confidence MITRE techniques", value=False)
    items = []
    for r in rows:
        rec = storage.get_result(r["id"])
        if rec is not None:
            items.append({"label": r["filename"], "score": r["score"],
                          "level": r["level"], "result": rec["result"]})
    if not items:
        st.info("No analyses yet.")
    elif not kinds:
        st.info("Pick at least one type to show.")
    else:
        dot, count = build_dot(items, kinds, only_shared, include_low)
        if count == 0:
            st.info("Nothing to draw for this selection. Try unticking 'Only items shared'.")
        else:
            st.graphviz_chart(dot)
            st.caption(f"{len(items)} APKs, {count} shared items. "
                       "Blue = IoCs, purple = libraries, orange = MITRE techniques.")
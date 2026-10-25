"""Kavach dashboard. Run with: streamlit run app.py"""
import hashlib
import os
import tempfile

import pandas as pd
import streamlit as st

from analyze import analyze
from analyzer import ai, storage
from analyzer.correlate import compare_apks, correlate_findings
from analyzer.graph import ALL_KINDS, build_dot
from analyzer.intel import lookup_hash
from analyzer.report import build_pdf
from analyzer.yara_gen import generate_yara

st.set_page_config(page_title="Kavach", page_icon="\U0001F6E1", layout="wide")
st.title("Kavach")
st.caption("Kavach (\u0915\u0935\u091a, armour): explainable Android APK triage for SOC and forensic teams")

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

def _run_lookup(sha256: str) -> None:
    st.session_state[f"intel_{sha256}"] = lookup_hash(sha256)


rows = storage.list_results()
tab_report, tab_compare, tab_graph, tab_ai = st.tabs(
    ["Report", "Compare", "Relationships", "AI Assistant"])

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
        intel_key = f"intel_{record['sha256']}"
        st.download_button(
            "Download PDF report",
            build_pdf(record["filename"], record["sha256"], res, st.session_state.get(intel_key),
                      st.session_state.get(f"ai_summary_{record['sha256']}")),
            file_name=f"{record['filename']}.report.pdf", mime="application/pdf")

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

        st.subheader("Correlated findings")
        correlations = correlate_findings(res)
        if correlations:
            for c in correlations:
                st.markdown(f"**{c['title']}** ({c['severity']})  \n{c['why']}  \n"
                            f"Evidence: {', '.join(c['evidence'])}")
        else:
            st.write("No combined patterns found.")
        st.caption("Correlations explain combinations of findings. They do not change the score.")

        left, right = st.columns(2)
        with left:
            with st.expander("Indicators of compromise", expanded=True):
                for key in ("urls", "ips", "domains"):
                    vals = res["iocs"].get(key, [])
                    st.markdown(f"**{key}** ({len(vals)})")
                    if vals:
                        st.code("\n".join(vals))
            with st.expander("Behavioural capabilities (API usage)", expanded=True):
                if res.get("capabilities"):
                    st.dataframe(pd.DataFrame([
                        {"capability": c["label"], "level": c["tier"], "status": c["status"],
                         "APIs": ", ".join(c["apis"][:3])}
                        for c in res["capabilities"]
                    ]), width="stretch", hide_index=True)
                    st.caption("Static: shows what the code can do. 'referenced only' means the "
                               "permission is not declared, usually unused library code.")
                else:
                    st.write("No sensitive API usage found.")
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
        with st.expander("Threat intelligence (hash lookup)"):
            st.caption("Only the SHA-256 hash is sent, never the file. "
                       "Needs VT_API_KEY and/or MB_AUTH_KEY in a .env file.")
            st.button("Look up hash", key=f"lookup_{record['sha256']}",
                      on_click=_run_lookup, args=(record["sha256"],))
            for item in st.session_state.get(intel_key) or []:
                line = f"**{item['source']}** ({item['status']}): {item['summary']}"
                if item["link"]:
                    line += f"  [open]({item['link']})"
                st.markdown(line)
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

    if len(items) >= 2:
        st.subheader("Direct links and weak similarities")
        pairs = compare_apks([{"label": it["label"], "result": it["result"]} for it in items])
        st.dataframe(pd.DataFrame([
            {"APK A": p["a"], "APK B": p["b"], "verdict": p["verdict"],
             "direct evidence": "; ".join(p["strong"]) or "-",
             "weak similarities": "; ".join(p["weak"]) or "-"}
            for p in pairs
        ]), width="stretch", hide_index=True)
        st.caption("Weak similarities alone are not evidence of a shared origin.")
        status = ai.ollama_status()
        if st.button("Explain relationships with AI", disabled=not status["available"]):
            try:
                with st.spinner("Asking the local model..."):
                    st.session_state["ai_links"] = ai.explain_links(pairs)
            except ai.AIError as exc:
                st.error(f"AI request failed: {exc}")
        if not status["available"]:
            st.caption(status["message"])
        links = st.session_state.get("ai_links")
        if links:
            st.info(links["text"])
            if links["unverified"]:
                st.warning("Not found in the data (unverified): " + ", ".join(links["unverified"]))
            st.caption("AI-generated. Verify against the evidence in the table.")

# ---------- AI assistant tab ----------
with tab_ai:
    st.write("The assistant explains Kavach's findings in plain language. It runs on a local model, "
             "so nothing leaves this machine. **It never changes the risk score**, and every identifier "
             "in its answers is checked against the report.")
    status = ai.ollama_status()
    if not status["available"]:
        st.info(f"{status['message']} Until then a rule-based summary is shown and the chat is off.")
    if not rows:
        st.info("No analyses yet. Upload an APK in the sidebar.")
    else:
        names = {r["id"]: r["filename"] for r in rows}
        pick = st.selectbox("APK", list(names), format_func=lambda i: names[i], key="ai_apk")
        rec = storage.get_result(pick)
        if rec is None:
            st.error("This analysis was not found in the database.")
            st.stop()
        a_res, sha = rec["result"], rec["sha256"]
        a_corr = correlate_findings(a_res)

        st.subheader("Investigation summary")
        if st.button("Generate summary", type="primary", key=f"sum_{sha}"):
            with st.spinner("Writing the summary..."):
                st.session_state[f"ai_summary_{sha}"] = ai.summarize(a_res, a_corr)
        summary = st.session_state.get(f"ai_summary_{sha}")
        if summary:
            if summary["source"] == "ai":
                st.caption(f"AI-generated by {summary['model']}. Verify against the evidence.")
            else:
                st.caption("Rule-based summary (no AI model used). " + summary.get("note", ""))
            st.write(summary["text"])
            if summary["unverified"]:
                st.warning("Not found in the report (unverified): " + ", ".join(summary["unverified"]))

        st.subheader("Ask about this APK")
        chat_key = f"chat_{sha}"
        history = st.session_state.setdefault(chat_key, [])
        cols = st.columns(3)
        for col, text in zip(cols, ["Why is this APK rated this way?", "Which evidence is strongest?",
                                    "What should I investigate next?"]):
            if col.button(text, key=f"{text}_{sha}", disabled=not status["available"]):
                st.session_state["pending_question"] = text
        question = st.chat_input("Ask a question about this APK", disabled=not status["available"]) \
            or st.session_state.pop("pending_question", None)
        if question and status["available"]:
            try:
                with st.spinner("Thinking..."):
                    answer = ai.ask(a_res, a_corr, question, history)
                history.append({"role": "user", "content": question})
                history.append({"role": "assistant", "content": answer["text"],
                                "unverified": answer["unverified"]})
            except ai.AIError as exc:
                st.error(f"AI request failed: {exc}")
        for turn in history:
            with st.chat_message(turn["role"]):
                st.write(turn["content"])
                if turn.get("unverified"):
                    st.warning("Not found in the report (unverified): " + ", ".join(turn["unverified"]))
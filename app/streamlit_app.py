"""Engineer triage dashboard."""
import sys
from html import escape
from pathlib import Path
from urllib.parse import urlencode

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from ai.copilot import ask
from shared import config

st.set_page_config(page_title="GraniteGuard | Fix this first", page_icon="🛡️", layout="wide")
st.markdown("<style>" + Path(__file__).with_name("style.css").read_text(encoding="utf-8") + "</style>", unsafe_allow_html=True)


def html(content):
    st.markdown(content, unsafe_allow_html=True)



def number(value, pattern):
    return "Unavailable" if pd.isna(value) else format(value, pattern)


def load():
    return (
        pd.read_csv(config.TOP500_CSV),
        pd.read_csv(config.EPSS_HISTORY_CSV) if config.EPSS_HISTORY_CSV.exists() else pd.DataFrame(columns=["cve_id", "month", "epss"]),
        pd.read_csv(config.THREAT_CARDS_CSV) if config.THREAT_CARDS_CSV.exists() else pd.DataFrame(columns=["cve_id", "attack_surface", "why_fix_first"]),
    )


try:
    top, hist, cards = load()
except FileNotFoundError:
    st.error("No data yet. Run `python train_and_predict.py` (Person 1) and `python -m ai.granite_briefs` (Person 2) to create data/processed.")
    st.stop()
except (pd.errors.ParserError, pd.errors.EmptyDataError, UnicodeDecodeError):
    st.error("A handoff CSV is empty or unreadable. Ask its owner to regenerate it.")
    st.stop()

from shared.contracts import TOP500_COLUMNS, EPSS_HISTORY_COLUMNS, THREAT_CARDS_COLUMNS
for frame, columns, label in [(top, TOP500_COLUMNS, "Ranking"), (hist, EPSS_HISTORY_COLUMNS, "History"), (cards, THREAT_CARDS_COLUMNS, "Threat cards")]:
    missing = set(columns) - set(frame.columns)
    if missing:
        st.error(f"{label}: missing columns {', '.join(sorted(missing))}")
        st.stop()
if top.empty or top.cve_id.isna().any() or top.cve_id.duplicated().any():
    st.error("Ranking must contain unique, nonempty CVE IDs.")
    st.stop()
for column in ["rank", "score", "cvss", "epss", "epss_momentum"]:
    top[column] = pd.to_numeric(top[column], errors="coerce")
if top[["rank", "score"]].isna().any().any():
    st.error("Rank and model score must be numeric.")
    st.stop()
top = top.sort_values("rank")
requested_cve = st.query_params.get("cve", "")
try:
    initial_budget = max(1, min(len(top), int(st.query_params.get("budget", 500))))
except (TypeError, ValueError):
    initial_budget = min(500, len(top))

def page_url(cve_id=""):
    params = {"budget": budget}
    if query:
        params["q"] = query
    for name, value in [("severity", severity_filter), ("exploit", exploit_filter), ("surface", surface_filter)]:
        params[name] = value
    if cve_id:
        params["cve"] = cve_id
    return "?" + urlencode(params)

def search_changed():
    st.query_params["q"] = st.session_state["header_search"]
    if "cve" in st.query_params:
        del st.query_params["cve"]

def supporting_information():
    help_column, method_column = st.columns(2)
    with help_column.expander("New here? Start with this"):
        st.write("A CVE identifies a software vulnerability. Click a finding to see why it ranks highly and how to investigate a fix. Use the slider to focus your queue; search applies within that budget.")
        st.write("Severity describes potential damage. EPSS estimates exploitation likelihood. The model ranking combines its supplied signals to order the queue.")
    with method_column.expander("Method & submission"):
        st.write("Evaluate model, CVSS, and EPSS on the same eligible population and temporal cutoff. Comparing only this shortlist cannot establish full-benchmark improvement. KEV absence does not prove absence of exploitation.")
        st.warning("The handoff lacks snapshot_month and feature provenance. Person 1 must confirm cutoff-safe features and audit current NIST descriptions, scores, status, product counts, and references for leakage.")
        st.write("Pending evidence: temporal validation, hits@500, precision@500, baseline results, Granite model identifiers, and verified service calls.")
        eligible = False
        scoreboard_path = config.RAW_DIR / "scoreboard_2026.csv"
        if scoreboard_path.exists():
            try:
                scoreboard = pd.read_csv(scoreboard_path, usecols=["cve_id"])
                eligible = len(top) == 500 and top.cve_id.isin(scoreboard.cve_id).all()
            except (ValueError, pd.errors.ParserError):
                st.error("Cannot read scoreboard eligibility list.")
        st.download_button("Download judge top500.csv", top[["cve_id"]].to_csv(index=False), file_name="top500.csv", mime="text/csv", disabled=not eligible)
        st.caption("Export requires 500 unique, non-demo IDs in data/raw/scoreboard_2026.csv. It contains only cve_id. Eligibility does not verify temporal leakage or model quality.")


def render_history(cve):
    series = hist[hist["cve_id"] == cve].copy()
    series["month"] = pd.to_datetime(series["month"], errors="coerce")
    series["epss"] = pd.to_numeric(series["epss"], errors="coerce")
    series = series.dropna().sort_values("month")
    if not series.empty:
        chart = go.Figure(go.Scatter(
            x=series["month"].dt.strftime("%Y-%m-%d").tolist(),
            y=series["epss"].tolist(), mode="lines+markers",
        ))
        chart.update_traces(line_color="#0f62fe", fill="tozeroy", fillcolor="rgba(15,98,254,0.07)", hovertemplate="%{x}<br>EPSS: %{y:.2%}<extra></extra>")
        if len(series) == 1:
            chart = go.Figure(go.Bar(x=series["month"].dt.strftime("%b %Y").tolist(), y=series["epss"].tolist(), marker_color="#0f62fe", width=0.35, text=series["epss"].map(lambda value: f"{value:.2%}").tolist(), textposition="outside", hovertemplate="%{x}<br>EPSS: %{y:.2%}<extra></extra>"))
            chart.update_yaxes(range=[0, 1.05])
        chart.update_layout(title="EPSS at the snapshot" if len(series) == 1 else "How EPSS changed", xaxis_title=None, yaxis_title="EPSS", yaxis_tickformat=".0%", height=280, paper_bgcolor="#ffffff", plot_bgcolor="#ffffff", font_color="#444444", margin=dict(l=10,r=10,t=45,b=10))
        chart.update_xaxes(gridcolor="#eeeeee")
        chart.update_yaxes(gridcolor="#eeeeee")
        st.plotly_chart(chart, use_container_width=True)
        st.caption("Only one snapshot is available for this CVE; a trend cannot be inferred." if len(series) == 1 else "Monthly history supplied by the team. EPSS changed models in March 2025; this chart does not prove exploitation.")
    else:
        st.info("EPSS history pending from Person 1.")


def render_exploration(cve, candidates):
    chart_mode = st.selectbox("Explore the signals", ["Selected CVE snapshot", "Compare EPSS", "Severity vs. likelihood", "Historical trend"], key="chart_mode")
    selected_row = top.loc[top.cve_id == cve].iloc[0]
    chart = None
    if chart_mode == "Selected CVE snapshot":
        if pd.isna(selected_row["epss"]):
            st.info("EPSS is unavailable for this vulnerability.")
            return
        chart = go.Figure(go.Bar(x=[cve], y=[float(selected_row["epss"])], marker_color="#0f62fe", width=0.35, text=[number(selected_row["epss"], ".2%")], textposition="outside"))
        chart.update_layout(title="EPSS in the ranked dataset", yaxis_tickformat=".0%", yaxis_range=[0, 1.05])
    elif chart_mode == "Compare EPSS":
        limit = st.selectbox("Findings to compare", [5, 10, 20], index=1)
        comparison = candidates.head(limit).dropna(subset=["epss"])
        if comparison.empty:
            st.info("No EPSS values are available in this selection.")
            return
        chart = go.Figure(go.Bar(x=comparison.epss.tolist(), y=comparison.cve_id.tolist(), orientation="h", marker_color=["#0f62fe" if item == cve else "#a8c7fa" for item in comparison.cve_id], hovertemplate="%{y}<br>EPSS: %{x:.2%}<extra></extra>"))
        chart.update_layout(title=f"First {len(comparison)} ranked findings with EPSS", xaxis_tickformat=".0%", yaxis_autorange="reversed")
        st.caption("Uses the first findings in your filtered ranking, not an EPSS-sorted list. Missing EPSS values are omitted; snapshot months may differ.")
    elif chart_mode == "Severity vs. likelihood":
        comparison = candidates.dropna(subset=["cvss", "epss"])
        chart = go.Figure(go.Scatter(x=comparison.cvss.tolist(), y=comparison.epss.tolist(), text=comparison.cve_id.tolist(), mode="markers", marker=dict(color="#a8c7fa", size=8, opacity=0.65), hovertemplate="%{text}<br>CVSS: %{x:.1f}<br>EPSS: %{y:.2%}<extra></extra>", name="Filtered findings"))
        if pd.notna(selected_row["cvss"]) and pd.notna(selected_row["epss"]):
            chart.add_trace(go.Scatter(x=[float(selected_row["cvss"])], y=[float(selected_row["epss"])], text=[cve], mode="markers", marker=dict(color="#0f62fe", size=14, symbol="diamond"), name="Selected CVE", hovertemplate="%{text}<br>CVSS: %{x:.1f}<br>EPSS: %{y:.2%}<extra></extra>"))
        chart.update_layout(title="Impact and likelihood are different", xaxis_title="Severity (CVSS)", xaxis_range=[0,10.3], yaxis_title="EPSS", yaxis_tickformat=".0%", yaxis_range=[0,1.05], showlegend=False)
        st.caption(f"{len(comparison)} findings with both scores. Blue diamond: selected CVE. Hover to inspect a point. This comparison does not measure model accuracy.")
    else:
        observations = hist.loc[hist.cve_id == cve].copy()
        observations["month"] = pd.to_datetime(observations["month"], errors="coerce")
        observations["epss"] = pd.to_numeric(observations["epss"], errors="coerce")
        count = observations.dropna(subset=["month", "epss"]).month.nunique()
        if count < 2:
            st.info(f"Historical trend unavailable: {count} valid monthly snapshot(s). At least two distinct months are needed for a line graph. Use Snapshot or Compare EPSS for the available data.")
        else:
            render_history(cve)
        return
    chart.update_layout(height=340 if chart_mode != "Compare EPSS" else max(300, 28 * len(comparison)), paper_bgcolor="#fff", plot_bgcolor="#fff", font_color="#444", margin=dict(l=10,r=10,t=50,b=15))
    chart.update_xaxes(gridcolor="#eee")
    chart.update_yaxes(gridcolor="#eee")
    st.plotly_chart(chart, use_container_width=True)

budget = initial_budget
with st.container(key="site_header"):
    brand, search = st.columns([5, 3], vertical_alignment="center")
    with brand:
        html('<div class="gg-brand"><span class="gg-mark">G</span>GraniteGuard</div><div class="gg-brand-sub">VULNERABILITY INTELLIGENCE</div>')
    with search:
        query = st.text_input("Find a vulnerability", value=st.query_params.get("q", ""), placeholder="Search CVE or description...", label_visibility="visible", key="header_search", on_change=search_changed)

with st.container(key="top_tools"):
    html('<div class="gg-top-tools"><span class="gg-workspace">&#9678; &nbsp; Priority workspace</span><span><b>YOUR WORKFLOW</b> &nbsp; 01 Focus the queue &nbsp; / &nbsp; 02 Inspect the evidence &nbsp; / &nbsp; 03 Plan the next action</span></div>')
    supporting_information()


if not requested_cve:
    first = top.iloc[0]
    html('<div class="gg-topbar"><span>WORKSPACE &nbsp; / &nbsp; OVERVIEW</span><span class="gg-status">' + 'Imported dataset' + '</span></div>')
    html(f'''<section class="gg-hero"><div><div class="gg-kicker">A clearer signal. A smarter next step.</div>
    <h1>Less noise.<br><span>Know what to fix first.</span></h1>
    <p>Turn a long list of vulnerabilities into a focused investigation. See the signals, understand the priority, and make your next decision.</p></div>
    <div class="gg-hero-right"><div class="gg-kicker">First in your ranking</div><div class="gg-focus">{escape(str(first['cve_id']))}</div>
    <div class="gg-focus-meta"><span class="gg-pill">PRIORITY #1</span><span class="gg-pill">EPSS {number(first['epss'], '.2%')}</span></div>
    <p>Start with the leading finding, then inspect the evidence behind its position.</p></div></section>''')
    html('<div class="gg-demo"><strong>Imported data</strong><span>Team-supplied rankings and explanations. Provenance and evaluation are available in Method & submission.</span></div>')
    metrics = [
        ("Vulnerabilities", f"{len(top):,}", "In the supplied ranking"),
        ("Your review queue", str(budget), "Highest-ranked findings"),
        ("Critical severity", str(int((top.cvss >= 9).sum())), "CVSS ≥ 9 · across all findings"),
        ("Missing severity", str(int(top.cvss.isna().sum())), "Unknown does not mean safe"),
    ]
    metrics_slot = st.empty()


if not requested_cve:
    slider_column, refresh_column, _ = st.columns([3, 1.3, 5], vertical_alignment="center")
    with slider_column, st.container(key="queue_controls"):
        html('<div class="gg-kicker">Shape your queue</div>')
        budget = st.slider("Review budget", 1, len(top), initial_budget, help="Choose how many ranked vulnerabilities to display.") if len(top) > 1 else 1
        st.caption("Drag the slider to adjust how many ranked findings you review.")
    with refresh_column:
        st.button("Refresh data", use_container_width=True)
    metrics[1] = ("Your review queue", str(budget), "Highest-ranked findings")
    metrics_slot.markdown('<div class="gg-stats">' + ''.join(f'<div class="gg-stat"><div class="gg-stat-label">{label}</div><div class="gg-stat-value">{value}</div><div class="gg-stat-note">{note}</div></div>' for label,value,note in metrics) + '</div>', unsafe_allow_html=True)
surface = cards.drop_duplicates("cve_id").set_index("cve_id")["attack_surface"].fillna("").to_dict() if not cards.empty else {}
severity_options = ["All severities", "Critical (9-10)", "High (7-8.9)", "Medium (4-6.9)", "Low (0.1-3.9)", "None (0)", "Unknown"]
exploit_options = ["Any code status", "Public code reported", "No public code tag"]
surface_options = ["All attack surfaces"] + sorted({tag.strip() for value in surface.values() for tag in str(value).split(";") if tag.strip() and tag.strip() != "public exploit code"})
def filter_value(name, options):
    value = st.query_params.get(name, options[0])
    return value if value in options else options[0]
severity_filter = filter_value("severity", severity_options)
exploit_filter = filter_value("exploit", exploit_options)
surface_filter = filter_value("surface", surface_options)
if not requested_cve:
    severity_col, exploit_col, surface_col = st.columns(3)
    with severity_col:
        severity_filter = st.selectbox("Severity", severity_options, index=severity_options.index(severity_filter))
    with exploit_col:
        exploit_filter = st.selectbox("Public exploit / detection code", exploit_options, index=exploit_options.index(exploit_filter))
    with surface_col:
        surface_filter = st.selectbox("Attack surface", surface_options, index=surface_options.index(surface_filter))
    st.caption("Filters apply within your review budget. Code status and attack-surface tags come from supplied threat cards; an absent tag does not prove absence of exploit code.")
queue = top.head(budget)
if query:
    queue = queue[queue.cve_id.str.contains(query, case=False, regex=False, na=False) | queue.description.str.contains(query, case=False, regex=False, na=False)]

surface = cards.drop_duplicates("cve_id").set_index("cve_id")["attack_surface"].fillna("").to_dict() if not cards.empty else {}

if severity_filter == "Unknown":
    queue = queue[queue.cvss.isna()]
elif severity_filter != "All severities":
    bounds = {"Critical (9-10)": (9, 10.1), "High (7-8.9)": (7, 9), "Medium (4-6.9)": (4, 7), "Low (0.1-3.9)": (0.1, 4), "None (0)": (0, 0.1)}
    lo, hi = bounds[severity_filter]
    queue = queue[(queue.cvss >= lo) & (queue.cvss < hi)]
tags_by_cve = queue.cve_id.map(lambda item: {tag.strip() for tag in str(surface.get(item, "")).split(";")})
if exploit_filter != "Any code status":
    has_code = tags_by_cve.map(lambda tags: "public exploit code" in tags)
    queue = queue[has_code if exploit_filter == "Public code reported" else ~has_code]
if surface_filter != "All attack surfaces":
    queue = queue[queue.cve_id.map(lambda item: surface_filter in {tag.strip() for tag in str(surface.get(item, "")).split(";")})]

if not requested_cve:
    list_column, preview_column = st.columns([6, 4], gap="large")
    with list_column:
        html(f'<div class="gg-issue-toolbar"><strong>&#9678; &nbsp; {len(queue)} vulnerabilities</strong><span>Ranked by priority &middot; click a finding to investigate</span></div>')
        if queue.empty:
            st.info("No matches within this budget. Clear search or increase the budget.")
        issue_rows = []
        for row in queue.itertuples():
            tags = [tag.strip() for tag in str(surface.get(row.cve_id, "")).split(";") if tag.strip()]
            description = str(row.description) if pd.notna(row.description) else "Description pending"
            summary = description[:185] + ("..." if len(description) > 185 else "")
            badges = ''.join(f'<span class="gg-issue-tag">{escape(tag)}</span>' for tag in tags[:4])
            issue_rows.append(f'''<a class="gg-issue-row" href="{escape(page_url(row.cve_id), quote=True)}" target="_self">
    <span class="gg-issue-icon" aria-hidden="true">&#9678;</span><div class="gg-issue-body">
    <div class="gg-issue-title">{escape(row.cve_id)} <span class="gg-issue-rank">#{int(row.rank)}</span></div>
    <div class="gg-issue-summary">{escape(summary)}</div><div class="gg-issue-meta">{badges}<span>Published {escape(str(row.published_date))}</span></div></div>
    <div class="gg-issue-signals"><strong>CVSS {number(row.cvss, '.1f')}</strong><span>EPSS {number(row.epss, '.2%')}</span><span class="gg-issue-open">View investigation &rarr;</span></div></a>''')
        html('<div class="gg-issue-list gg-issue-scroll">' + ''.join(issue_rows) + '</div>')
        st.caption("The ranking orders investigation, not confirmed attacks. Public code can include scanner templates as well as exploits. Missing signals are not proof of safety.")

    with preview_column:
        html('<div class="gg-section"><h2>Investigation preview</h2><span class="gg-count">Signals &amp; context</span></div>')
        if queue.empty:
            st.info("Clear your search or increase the budget to preview a finding.")
        else:
            preview_cve = st.selectbox("Preview a vulnerability", queue.cve_id.tolist(), key="queue_preview")
            preview_row = top.loc[top.cve_id == preview_cve].iloc[0]
            html(f'<div class="gg-detail"><div class="gg-kicker">Priority #{int(preview_row["rank"])}</div><h3>{escape(preview_cve)}</h3><div class="gg-detail-metrics"><div><span>CVSS / 10</span><b>{number(preview_row["cvss"], ".1f")}</b></div><div><span>EPSS</span><b>{number(preview_row["epss"], ".2%")}</b></div></div></div>')
            render_exploration(preview_cve, queue)
            st.markdown("**Why fix this first**")
            preview_card = cards[cards.cve_id == preview_cve]
            if not preview_card.empty:
                st.caption("IBM Granite - team-supplied explanation")
                st.write(preview_card.iloc[0]["why_fix_first"])
            else:
                st.info("No explanation has been supplied for this finding yet.")
            with st.expander("Vulnerability description"):
                st.write(preview_row["description"])
            html(f'<a class="gg-open-detail" href="{escape(page_url(preview_cve), quote=True)}" target="_self">Open fix guidance &amp; Copilot &rarr;</a>')
            st.caption("The full investigation includes remediation guidance, reference lookups, and Ask Copilot.")
    st.stop()

match = top.loc[top.cve_id == requested_cve]
html(f'<a class="gg-back" href="{escape(page_url(), quote=True)}" target="_self">&larr; Back to vulnerabilities</a>')
if match.empty:
    st.warning("This vulnerability is not in the current ranking. Return to the list to choose an available finding.")
    st.stop()
cve = requested_cve
selected = match.iloc[0]
html(f'<div class="gg-topbar"><span>VULNERABILITIES / INVESTIGATION</span><span class="gg-count">Priority #{int(selected["rank"])}</span></div>')
st.title(cve)
st.caption("Understand the priority. Check the affected software. Plan a verified fix.")
main, metadata = st.columns([3, 1], gap="large")
with metadata:
    html('<div class="gg-kicker">Finding details</div>')
    st.metric("Priority rank", f"#{int(selected['rank'])}")
    st.metric("Severity / 10", number(selected["cvss"], ".1f"))
    st.metric("EPSS likelihood", number(selected["epss"], ".2%"))
    st.caption("EPSS estimates exploitation likelihood over 30 days; it is not severity.")
    st.divider()
    st.markdown("**Attack surface**")
    st.write(surface.get(cve) or "Not supplied")
    st.markdown("**Published**")
    st.write(str(selected["published_date"]))
    st.markdown("**Reference lookup**")
    st.link_button("NVD vulnerability record", f"https://nvd.nist.gov/vuln/detail/{cve}")
    st.link_button("CVE.org record", f"https://www.cve.org/CVERecord?id={cve}")
    st.caption("External record lookups, not verified patch instructions. Follow the vendor advisories linked in the records.")

with main:
    overview, remediation, evidence, copilot = st.tabs(["Why this first", "How to fix", "Signals", "Ask Copilot"])
    with overview:
        st.subheader("What is affected?")
        st.write(selected["description"])
        card = cards[cards["cve_id"] == cve]
        if not card.empty:
            st.markdown("**Why fix this first**")
            st.caption("IBM Granite - team-supplied explanation, not independently verified")
            st.write(card.iloc[0]["why_fix_first"])
        else:
            st.info("IBM Granite brief pending from Person 2.")

        html('<div class="gg-brief"><div class="gg-kicker">Your next step</div><p>Check whether the affected software exists in your environment. Confirm exposure and vendor guidance before scheduling a fix.</p></div>')
        st.caption("A ranking supports investigation; it does not establish that an attack has occurred.")
    with remediation:
        st.subheader("Plan the fix")
        st.caption("Use this investigation checklist with the vendor advisory. Applicability, fixed versions, and temporary controls must be confirmed for your environment.")
        card = cards[cards["cve_id"] == cve]
        if not card.empty:
            with st.container(border=True):
                st.markdown("**Available Granite guidance**")
                st.write(card.iloc[0]["why_fix_first"])
                st.caption("This is the supplied threat brief in full. It may include mitigation suggestions; it is not a verified remediation procedure.")
        else:
            st.info("No CVE-specific remediation brief has been supplied yet.")
        st.markdown("""
**1. Confirm applicability**
Match the affected product, installed version, and configuration against the official CVE record and vendor advisory.

**2. Identify the vendor-supported fix**
Check the vendor's fixed release or patch and its prerequisites. This dataset does not provide independently verified patch versions or installation commands.

**3. Plan the change**
Follow your team's backup, testing, and rollback process. If patching must wait, use only temporary controls supported by the vendor advisory and record the remaining exposure.

**4. Verify and document**
Confirm the installed version and relevant configuration after the change, run your approved checks, and record the evidence before considering the issue resolved.
""")
        st.info("Need more context? Use Ask Copilot for a CVE-specific question. Verify any proposed fix against the original vendor source.")
    with evidence:
        render_history(cve)

    with copilot:
        st.markdown("**Ask about this vulnerability**")
        st.caption("IBM Granite + Snowflake Copilot · answers cite their source CVEs")
        st.caption("Validate mitigation advice against vendor guidance before acting.")
        messages = st.session_state.setdefault("chats", {}).setdefault(cve, [])
        for message in messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])
        with st.form(f"question_{cve}", clear_on_submit=True):
            q = st.text_input("Question", placeholder="What vendor-supported fix is documented for this CVE, and what is the source?")
            submitted = st.form_submit_button("Ask Copilot")
        if submitted and q.strip():
            if not (config.env("COPILOT_URL") and config.env("COPILOT_KEY")):
                st.info("Copilot is offline: set COPILOT_URL and COPILOT_KEY in .env (from Person 2). No generated answer has been substituted.")
            else:
                try:
                    with st.spinner("IBM Granite is searching Snowflake…"):
                        answer = ask(cve, q.strip())
                    messages.extend([{"role": "user", "content": q.strip()}, {"role": "assistant", "content": answer}])
                    st.rerun()
                except Exception:
                    st.error("Copilot request failed. Check backend configuration and retry.")

html('<div class="gg-footer"><span>GRANITEGUARD &nbsp; / &nbsp; Evidence before action.</span><span>IBM Granite · Tiger Data · Snowflake &nbsp; | &nbsp; ' + 'Team integration stack' + '</span></div>')

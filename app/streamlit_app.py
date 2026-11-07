"""Engineer triage dashboard."""
import sys
from html import escape
from pathlib import Path

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
with st.sidebar:
    html('<div class="gg-brand"><span class="gg-mark">G</span>GraniteGuard</div><div class="gg-brand-sub">VULNERABILITY INTELLIGENCE</div><div class="gg-nav">◎ &nbsp; Priority workspace</div>')
    html('<div class="gg-kicker">Shape your queue</div>')
    query = st.text_input("Find a vulnerability", placeholder="Search CVE or description…")
    budget = st.slider("Review budget", 1, len(top), min(500, len(top)), help="Starts at 500 findings, or all available if fewer. Drag the slider to adjust how many you review. Search applies within this budget.") if len(top) > 1 else 1
    st.caption("Drag the slider to adjust how many ranked findings you review.")
    st.button("↻ Refresh data", use_container_width=True)
    with st.expander("New here? Start with this"):
        st.write("A CVE is an identifier for a software vulnerability. Choose one from the investigation selector to see its signals and explanation.")
        st.write("Severity describes potential damage. EPSS estimates exploitation likelihood. The model ranking combines its supplied signals to order the queue.")
    html('<div class="gg-sidebar-foot">YOUR WORKFLOW<br>01 &nbsp; Focus the queue<br>02 &nbsp; Inspect the evidence<br>03 &nbsp; Plan the next action</div>')

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
html('<div class="gg-stats">' + ''.join(f'<div class="gg-stat"><div class="gg-stat-label">{label}</div><div class="gg-stat-value">{value}</div><div class="gg-stat-note">{note}</div></div>' for label,value,note in metrics) + '</div>')
queue = top.head(budget)
if query:
    queue = queue[queue.cve_id.str.contains(query, case=False, regex=False, na=False) | queue.description.str.contains(query, case=False, regex=False, na=False)]

with st.sidebar.expander("Method & submission"):
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

if queue.empty:
    st.info("No matches within this budget. Clear search or increase the budget.")
    st.stop()

left, right = st.columns([6, 5], gap="large")
with right:
    html('<div class="gg-section"><h2>Investigate</h2><span class="gg-count">CVE detail</span></div>')
    cve = st.selectbox("Choose a vulnerability", queue["cve_id"].tolist())
selected = top.loc[top.cve_id == cve].iloc[0]
with left:
    html(f'<div class="gg-section"><h2>Priority queue</h2><span class="gg-count">{len(queue)} findings</span></div>')
    st.caption("Ordered by model rank. Your selected finding is highlighted.")
    # Score is a rank average (0.98-1.00 for every row) and 2026 has no EPSS history, so show
    # signals an engineer can act on instead: public exploit code and the attack surface tags.
    surface = cards.set_index("cve_id")["attack_surface"].to_dict() if not cards.empty else {}
    headers = ["Rank", "Vulnerability", "CVSS", "EPSS", "Exploit code", "Attack surface"]
    rows = []
    for row in queue.itertuples():
        tags = [t.strip() for t in str(surface.get(row.cve_id, "")).split(";") if t.strip()]
        has_exploit = "public exploit code" in tags
        tags = [t for t in tags if t != "public exploit code"]
        values = [number(row.rank, ".0f"), row.cve_id,
                  number(row.cvss, ".1f"), number(row.epss, ".2%"),
                  "✓ Public" if has_exploit else "None known",
                  ", ".join(tags) if tags else "Pending"]
        style = ' class="selected"' if row.cve_id == cve else ""
        cells = [escape(str(value)) for value in values]
        risk_class = "critical" if pd.notna(row.cvss) and row.cvss >= 9 else ""
        cells[2] = f'<span class="gg-risk {risk_class}">{cells[2]}</span>'
        cells[4] = f'<span class="{"gg-up" if has_exploit else "gg-down"}">{cells[4]}</span>'
        rows.append(f"<tr{style}>" + "".join(f"<td>{value}</td>" for value in cells) + "</tr>")
    st.markdown('<div class="gg-table-wrap">'
                '<table class="gg-table"><thead><tr>' + ''.join(f'<th>{h}</th>' for h in headers)
                + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>', unsafe_allow_html=True)
    with st.expander("What do these numbers mean?"):
        st.write("**Rank:** our model's order out of 72,670 vulnerabilities published in 2026; 1 = fix first. **Severity (CVSS):** potential impact on a 0–10 scale. **EPSS:** estimated probability of exploitation in the next 30 days.")
        st.write("**Exploit code:** public attack or detection code existed at the snapshot month (Exploit-DB, Metasploit, Nuclei or a GitHub proof of concept). **Attack surface:** how it is reached, from CVSS fields and the description: remote, pre-auth, no user click, RCE.")
    st.caption("Select a CVE in Investigate to explore its details. Scores remain fixed until the dataset changes.")

with right:
    html(f'''<div class="gg-detail"><div class="gg-kicker">Investigation / selected finding</div>
<h3>{escape(cve)}</h3><div class="gg-detail-metrics">
<div><span>PRIORITY RANK</span><b>#{int(selected['rank'])}</b></div>
<div><span>SEVERITY / 10</span><b>{number(selected['cvss'], '.1f')}</b></div>
<div><span>EPSS LIKELIHOOD</span><b>{number(selected['epss'], '.2%')}</b></div></div></div>''')
    overview, evidence, copilot = st.tabs(["Overview", "Signal history", "Ask Copilot"])
    with overview:
        st.write(selected["description"])
        card = cards[cards["cve_id"] == cve]
        if not card.empty:
            st.markdown("**Why fix this first**")
            st.caption(card.iloc[0]["attack_surface"])
            st.write(card.iloc[0]["why_fix_first"])
        else:
            st.info("IBM Granite brief pending from Person 2.")

        html('<div class="gg-brief"><div class="gg-kicker">Your next step</div><p>Check whether the affected software exists in your environment. Confirm exposure and vendor guidance before scheduling a fix.</p></div>')
        st.caption("A ranking supports investigation; it does not establish that an attack has occurred.")
    with evidence:
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
            chart.update_layout(title="How EPSS changed", xaxis_title=None, yaxis_title="EPSS", yaxis_tickformat=".0%", height=330, paper_bgcolor="#ffffff", plot_bgcolor="#ffffff", font_color="#444444", margin=dict(l=10,r=10,t=45,b=10))
            chart.update_xaxes(gridcolor="#eeeeee")
            chart.update_yaxes(gridcolor="#eeeeee")
            st.plotly_chart(chart, use_container_width=True)
            st.caption("Monthly history supplied by the team. EPSS changed models in March 2025; this chart does not prove exploitation.")
        else:
            st.info("EPSS history pending from Person 1.")

    with copilot:
        st.markdown("**Ask about this vulnerability**")
        st.caption("IBM Granite + Snowflake Copilot · answers cite their source CVEs")
        st.caption("Validate mitigation advice against vendor guidance before acting.")
        messages = st.session_state.setdefault("chats", {}).setdefault(cve, [])
        for message in messages:
            with st.chat_message(message["role"]):
                st.write(message["content"])
        with st.form(f"question_{cve}", clear_on_submit=True):
            q = st.text_input("Question", placeholder="What evidence supports prioritizing this CVE?")
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

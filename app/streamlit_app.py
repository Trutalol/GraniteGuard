"""Engineer triage dashboard."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
import plotly.express as px
import streamlit as st

from ai.copilot import ask
from shared import config

st.set_page_config(page_title="CVE Triage", layout="wide")


@st.cache_data
def load():
    return (
        pd.read_csv(config.TOP500_CSV),
        pd.read_csv(config.EPSS_HISTORY_CSV),
        pd.read_csv(config.THREAT_CARDS_CSV),
    )


try:
    top, hist, cards = load()
except FileNotFoundError:
    st.error("No data yet. Run `python -m shared.sample_data` for fake data.")
    st.stop()

st.title("Fix This First: Top 500 CVEs")

left, right = st.columns([3, 2])
with left:
    st.dataframe(top[["rank", "cve_id", "score", "cvss", "epss", "epss_momentum"]],
                 hide_index=True, use_container_width=True, height=520)

with right:
    cve = st.selectbox("Pick a CVE", top["cve_id"])
    card = cards[cards["cve_id"] == cve]
    if not card.empty:
        st.subheader("Why fix this first")
        st.caption(card.iloc[0]["attack_surface"])
        st.write(card.iloc[0]["why_fix_first"])

    series = hist[hist["cve_id"] == cve]
    if not series.empty:
        st.plotly_chart(px.line(series, x="month", y="epss", title="EPSS over time"),
                        use_container_width=True)

    st.subheader("Ask Copilot")
    q = st.text_input("e.g. What's the workaround if we can't patch?")
    if q:
        st.write(ask(cve, q))

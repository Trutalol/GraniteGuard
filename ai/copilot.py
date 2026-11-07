"""The 'Ask Copilot' backend the dashboard calls.

Person 3 only needs:  from ai.copilot import ask

The heavy part (Granite + Snowflake vector search) runs in ai/serve.py on a GPU.
This module just calls it, so the dashboard laptop needs no GPU and no Snowflake keys.
Set COPILOT_URL and COPILOT_KEY in .env (ai.serve prints both).
"""
from shared import config


def ask_full(question: str, timeout: int = 120) -> dict:
    """Full response: {"answer", "sources": [{cve_id, rank, score, ibm_xforce_url, reference_urls}],
    "unverified_citations"}."""
    import requests

    url = (config.env("COPILOT_URL") or "").rstrip("/")
    key = config.env("COPILOT_KEY")
    if not url or not key:
        return {"answer": "(copilot offline: set COPILOT_URL and COPILOT_KEY in .env)",
                "sources": [], "unverified_citations": []}
    try:
        r = requests.post(f"{url}/ask", json={"question": question},
                          headers={"x-api-key": key}, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as exc:  # keep the dashboard alive during the demo
        return {"answer": f"(copilot unavailable: {exc})", "sources": [], "unverified_citations": []}


def ask(cve_id: str, question: str) -> str:
    """Answer an engineer's question about one CVE. Returns markdown text with sources."""
    if cve_id and cve_id.upper() not in question.upper():
        question = f"{question} (about {cve_id})"
    res = ask_full(question)
    if not res["sources"]:
        return res["answer"]
    src = ", ".join(f"{s['cve_id']} (rank {s['rank']})" for s in res["sources"])
    return f"{res['answer']}\n\n*Sources: {src}*"

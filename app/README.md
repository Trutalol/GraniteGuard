# Person 3: dashboard and pitch

From the GraniteGuard repository root in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r app/requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app/streamlit_app.py
```

If `py` is unavailable, install Python and reopen the terminal.

## Team handoffs

Person 1 supplies `data/processed/top500.csv` with the full shared ranking contract, and `epss_history.csv`. Person 2 supplies `threat_cards.csv` and a working `ai.copilot.ask(cve_id, question)` backend. Missing charts or cards show pending states. Reload data after replacing files.

The judge CSV differs from the internal ranking: it has only `cve_id`. Place the original scoreboard at `data/raw/scoreboard_2026.csv` to enable eligibility checking. Export requires 500 unique eligible IDs. A completed leakage audit is still required.

The dashboard provides search, review budget, metrics, CVE details, EPSS chart, threat briefs, and expandable Copilot with per-CVE session history. Copilot calls occur only on form submission. To use Snowflake, install the Snowflake connector and configure the backend environment as described by Person 2.

## Before the demo

1. Verify the real ranking, history and Granite cards load (top row CVE-2026-8037).
2. Search for an existing and a nonexistent CVE; adjust the budget.
3. Select CVEs with and without history/cards.
4. Verify Copilot offline state, then test one real call with Person 2.
5. Validate the export header, 500 unique eligible rows, and rank order.
6. Obtain Person 1's temporal evaluation and Person 2's actual Granite model/run evidence.
7. Complete the Devpost placeholders and record the demo script.

The current backend uses the Snowflake Python connector, not a REST RAG endpoint. Do not present CSV loading as a verified Tiger Data connection.

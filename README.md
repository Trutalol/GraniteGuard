# CVE Triage: "Fix This First"

Ranks the top 500 CVEs most likely to be weaponized, explains why with IBM Granite,
and lets engineers ask a Snowflake-backed copilot how to mitigate them.

## Who owns what

| Folder | Owner | What lives here |
|---|---|---|
| `pipeline/` | **Person 1**, ML & Time-Series Lead | Tiger Data ingest, time-series SQL features, LightGBM ranking → `top500.csv` |
| `ai/` | **Person 2**, AI & Cloud Lead | Granite embeddings, Granite "why fix this first" briefs, Snowflake load + RAG copilot |
| `app/` + `docs/` | **Person 3**, Product & Pitch Lead | Streamlit dashboard, Devpost write-up, demo video script |
| `shared/` | Everyone (change by agreement) | Config, file paths, and the **data contracts** between the three parts |

Each person mostly edits only their own folder, so you rarely step on each other.

## How the parts connect

```
pipeline/  ──►  data/processed/top500.csv
                data/processed/epss_history.csv
                     │
ai/        ──►  data/processed/threat_cards.csv   (+ Snowflake tables)
                     │
app/       ◄──  reads all three files + calls ai/copilot.py
```

The exact columns of every handoff file are defined in `shared/contracts.py`.
**If you change a column, update the contract and tell the team.**

## Don't wait on each other

Run `python -m shared.sample_data` to write fake versions of every handoff file.
Person 2 and Person 3 can build against those on day one while Person 1 builds the real pipeline.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # fill in your own keys, never commit .env
python -m shared.sample_data
streamlit run app/streamlit_app.py
```

## Run the real thing end to end

```bash
bash scripts/run_all.sh
```

## Tests

```bash
pytest
```
`tests/test_contracts.py` checks that every handoff file has the columns the contract promises.

# pipeline/ (Person 1: ML & Time-Series Lead)

**Produces:** `data/processed/top500.csv`, `top500_submission.csv` (one column `cve_id`, the
Devpost file), `epss_history.csv`, `backtest_metrics.json`. Columns are in `shared/contracts.py`;
which data columns the model uses is in `docs/columns_used.md`.

Database: set `TIGER_DATABASE_URL` in `.env`. Works on Tiger Data (TimescaleDB, where
`exploit_signals` becomes a hypertable) or plain PostgreSQL 16, which is what the first run used.

Run order (put the unzipped CSVs in `data/raw/`):
1. `python -m pipeline.ingest_tiger` loads all CSVs (signals, vulnerabilities, KEV, scoreboard)
2. `python -m pipeline.features` runs `sql/cohorts.sql` (snapshot rows that mirror the 2026 rules)
   and `sql/features.sql` (as-of assigner KEV time series, EPSS percentiles), then exports parquet
3. `python -m pipeline.train_rank` fits the text prior, backtests on 2025, trains the final
   LightGBM + XGBoost + logistic ensemble and writes the outputs (about 5 minutes)

Model: rank average of LightGBM (monotone), XGBoost, a logistic model and the
"public exploit then EPSS" rule. Inputs: snapshot EPSS/exploit flags, a TF-IDF exploitability prior
refit each January on all earlier CVEs, as-of KEV counts for the vendor/product named in the
description and for the assigner, days since publish and days left until the judging cutoff.

Backtest (rank 2025 Jan-Sep CVEs, 45 later added to KEV by 2025-11-04):

| Ranking | Hits in top 500 | Top 243 (same share as 500 of 72,670) |
|---|---|---|
| CVSS 3 first | 7 | 7 |
| EPSS first | 8 | 8 |
| Public exploit then EPSS | 16 | 14 |
| **Ensemble** | **20** | **17** |

# pipeline/ (Person 1: ML & Time-Series Lead)

**You produce:** `data/processed/top500.csv` and `data/processed/epss_history.csv`
(columns in `shared/contracts.py`).

Run order:
1. `python -m pipeline.ingest_tiger` loads `data/raw/exploit_signals_2024.csv` and `_2025.csv` into Tiger Data
2. `python -m pipeline.features` runs `sql/features.sql` and saves the features
3. `python -m pipeline.train_rank` trains LightGBM and writes the two handoff files

TODO
- [ ] Ingest exploit signals into a Tiger Data hypertable
- [ ] EPSS velocity over 30/60/90 days
- [ ] PoC emergence lag (publish → GitHub/Nuclei/Metasploit)
- [ ] Train LightGBM, compare against CVSS and EPSS baselines
- [ ] Write top500.csv + epss_history.csv

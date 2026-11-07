"""One command for Person 1's part: load data, build leakage-free features, train, rank, chart.

    python train_and_predict.py            # full run (needs TIGER_DATABASE_URL and data/raw/*.csv)
    python train_and_predict.py --skip-ingest   # data already loaded in the database

Outputs (data/processed/): top500_submission.csv (Devpost, one column cve_id, highest score first),
top500.csv (with scores and context), epss_history.csv, backtest_metrics.json; docs/backtest_hits.png
"""
import sys

from pipeline import features, ingest_tiger, plot_backtest, train_rank


def main() -> None:
    if "--skip-ingest" not in sys.argv:
        ingest_tiger.main()      # 1. CSVs -> Tiger Data / PostgreSQL
    features.main()              # 2. snapshot rows that mirror the 2026 rules + as-of time-series features
    train_rank.main()            # 3. backtest, train LightGBM + XGBoost + logistic ensemble, write top 500
    plot_backtest.main()         # 4. chart vs CVSS / EPSS / exploit-then-EPSS


if __name__ == "__main__":
    main()

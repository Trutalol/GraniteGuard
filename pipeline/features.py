"""Run the time-series feature SQL and save the result."""
import pandas as pd
import psycopg

from shared import config

FEATURES_CSV = config.PROCESSED_DIR / "features.csv"


def main() -> None:
    sql = (config.ROOT / "pipeline" / "sql" / "features.sql").read_text()
    with psycopg.connect(config.env("TIGER_DATABASE_URL")) as conn:
        df = pd.read_sql(sql, conn)
    df.to_csv(FEATURES_CSV, index=False)
    print(f"Wrote {len(df)} rows to {FEATURES_CSV}")


if __name__ == "__main__":
    main()

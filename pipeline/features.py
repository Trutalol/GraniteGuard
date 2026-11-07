"""Run the cohort + time-series SQL in the database and export the feature tables."""
import pandas as pd
import psycopg

from shared import config

SNAPSHOT_PARQUET = config.PROCESSED_DIR / "snapshot_features.parquet"
CORPUS_PARQUET = config.PROCESSED_DIR / "text_corpus.parquet"
KEV_PARQUET = config.PROCESSED_DIR / "kev.parquet"


def query(conn, sql: str) -> pd.DataFrame:
    with conn.cursor() as cur:
        cur.execute(sql)
        cols = [d.name for d in cur.description]
        return pd.DataFrame(cur.fetchall(), columns=cols)


def main() -> None:
    with psycopg.connect(config.env("TIGER_DATABASE_URL"), autocommit=True) as conn:
        for name in ["cohorts.sql", "features.sql"]:
            conn.execute((config.ROOT / "pipeline" / "sql" / name).read_text())
        snap = query(conn, "SELECT * FROM snapshot_features")
        # Long history used only for the description/CWE "exploitability prior".
        corpus = query(conn, """
            SELECT v.cve_id, v.published, v.description, v.cwe_ids, v.assigner,
                   v.attack_vector, v.attack_complexity, v.privileges_required, v.user_interaction,
                   v.scope, k.date_added AS kev_date_added
            FROM vulnerabilities v
            LEFT JOIN (SELECT cve_id, min(date_added) date_added FROM known_exploited GROUP BY 1) k USING (cve_id)
            WHERE v.published >= '2016-01-01'""")
        kev = query(conn, "SELECT cve_id, vendor, product, date_added FROM known_exploited")
    snap.to_parquet(SNAPSHOT_PARQUET)
    corpus.to_parquet(CORPUS_PARQUET)
    kev.to_parquet(KEV_PARQUET)
    print(f"snapshot rows {len(snap)}, corpus rows {len(corpus)}, kev rows {len(kev)}")


if __name__ == "__main__":
    main()

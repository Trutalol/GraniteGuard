"""Apply pipeline/sql/timescale.sql to Tiger Data: compression + continuous aggregates.

    python -m pipeline.timescale_extras

Safe to run more than once: compression is only switched on if it isn't already, and the
continuous aggregates are created if missing, then refreshed.
"""
import psycopg

from shared import config


def statements(sql: str):
    body = "\n".join(line for line in sql.splitlines() if not line.strip().startswith("--"))
    return [s.strip() for s in body.split(";") if s.strip()]


def main() -> None:
    url = config.env("TIGER_DATABASE_URL")
    if not url:
        raise SystemExit("Set TIGER_DATABASE_URL in .env")
    sql = (config.ROOT / "pipeline" / "sql" / "timescale.sql").read_text()
    # refresh_continuous_aggregate can't run inside a transaction, so use autocommit
    with psycopg.connect(url, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute("""SELECT compression_enabled FROM timescaledb_information.hypertables
                       WHERE hypertable_name = 'exploit_signals'""")
        row = cur.fetchone()
        if row is None:
            raise SystemExit("exploit_signals is not a hypertable yet: run python train_and_predict.py first")
        cur.execute("SELECT pg_size_pretty(hypertable_size('exploit_signals'))")
        print("exploit_signals size before:", cur.fetchone()[0])
        for stmt in statements(sql):
            if stmt.upper().startswith("ALTER TABLE EXPLOIT_SIGNALS") and row[0]:
                print("compression already enabled, skipping ALTER")
                continue
            cur.execute(stmt)
            if cur.description:
                print(stmt.split()[0], "->", cur.fetchall())
        for view in ["signals_monthly", "assigner_signals_monthly"]:
            cur.execute(f"SELECT count(*) FROM {view}")
            print(view, "rows:", cur.fetchone()[0])


if __name__ == "__main__":
    main()

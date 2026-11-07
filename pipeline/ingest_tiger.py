"""Load the raw CSVs into Tiger Data (TimescaleDB) or any PostgreSQL 16 database.

Set TIGER_DATABASE_URL in .env. Without Tiger credentials, a local PostgreSQL works the same
(the schema only turns exploit_signals into a hypertable when timescaledb is installed).
"""
import psycopg

from shared import config

SIGNAL_FILES = ["exploit_signals_2024.csv", "exploit_signals_2025.csv"]


def copy_file(cur, table: str, columns: str, path) -> None:
    with path.open("rb") as f, cur.copy(
        f"COPY {table} ({columns}) FROM STDIN WITH (FORMAT csv, HEADER true, QUOTE '\"', ESCAPE '\"')"
    ) as copy:
        while chunk := f.read(1 << 20):
            copy.write(chunk)


def main() -> None:
    url = config.env("TIGER_DATABASE_URL")
    if not url:
        raise SystemExit("Set TIGER_DATABASE_URL in .env")
    schema = (config.ROOT / "pipeline" / "sql" / "schema.sql").read_text()
    with psycopg.connect(url, autocommit=True) as conn, conn.cursor() as cur:
        cur.execute(schema)

        # Signals: month arrives as YYYY-MM, so stage as text and convert to a DATE.
        cur.execute("""CREATE TEMP TABLE sig_stage (month TEXT, cve_id TEXT, epss DOUBLE PRECISION,
                       in_kev SMALLINT, exploitdb SMALLINT, metasploit SMALLINT, nuclei SMALLINT,
                       poc_github SMALLINT)""")
        for name in SIGNAL_FILES:
            copy_file(cur, "sig_stage", "month,cve_id,epss,in_kev,exploitdb,metasploit,nuclei,poc_github",
                      config.RAW_DIR / name)
            print(f"Staged {name}")
        cur.execute("""INSERT INTO exploit_signals
                       SELECT to_date(month || '-01', 'YYYY-MM-DD'), cve_id, epss, in_kev, exploitdb,
                              metasploit, nuclei, poc_github FROM sig_stage""")
        cur.execute("CREATE INDEX ON exploit_signals (cve_id, month DESC)")

        cur.execute("SELECT string_agg(column_name, ',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_name='vulnerabilities'")
        copy_file(cur, "vulnerabilities", cur.fetchone()[0], config.RAW_DIR / "vulnerabilities.csv")
        copy_file(cur, "known_exploited",
                  "cve_id,vendor,product,name,date_added,short_description,required_action,due_date,known_ransomware_use,cwe_ids",
                  config.RAW_DIR / "known_exploited.csv")
        copy_file(cur, "scoreboard", "cve_id,published,snapshot_month,epss,exploitdb,metasploit,nuclei,poc_github",
                  config.RAW_DIR / "scoreboard_2026.csv")
        cur.execute("CREATE INDEX ON vulnerabilities (published)")
        cur.execute("ANALYZE")
        for t in ["exploit_signals", "vulnerabilities", "known_exploited", "scoreboard"]:
            cur.execute(f"SELECT count(*) FROM {t}")
            print(t, cur.fetchone()[0])


if __name__ == "__main__":
    main()

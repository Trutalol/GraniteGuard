"""Load the raw exploit-signal CSVs into Tiger Data."""
import psycopg

from shared import config

RAW_FILES = ["exploit_signals_2024.csv", "exploit_signals_2025.csv"]


def main() -> None:
    url = config.env("TIGER_DATABASE_URL")
    if not url:
        raise SystemExit("Set TIGER_DATABASE_URL in .env")
    schema = (config.ROOT / "pipeline" / "sql" / "schema.sql").read_text()
    with psycopg.connect(url) as conn, conn.cursor() as cur:
        cur.execute(schema)
        for name in RAW_FILES:
            path = config.RAW_DIR / name
            # COPY is the fast path for millions of rows.
            # TODO: match the column list to the real CSV header.
            with path.open("rb") as f, cur.copy(
                "COPY exploit_signals FROM STDIN WITH (FORMAT csv, HEADER true)"
            ) as copy:
                while chunk := f.read(1 << 20):
                    copy.write(chunk)
            print(f"Loaded {name}")


if __name__ == "__main__":
    main()

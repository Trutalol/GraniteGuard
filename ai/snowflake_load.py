"""Load the ranked CVEs and threat cards into Snowflake."""
import pandas as pd

from shared import config


def connect():
    import snowflake.connector

    return snowflake.connector.connect(
        account=config.env("SNOWFLAKE_ACCOUNT"),
        user=config.env("SNOWFLAKE_USER"),
        password=config.env("SNOWFLAKE_PASSWORD"),
        warehouse=config.env("SNOWFLAKE_WAREHOUSE"),
        database=config.env("SNOWFLAKE_DATABASE"),
        schema=config.env("SNOWFLAKE_SCHEMA"),
    )


def main() -> None:
    from snowflake.connector.pandas_tools import write_pandas

    with connect() as conn:
        for name, path in [("TOP500", config.TOP500_CSV), ("THREAT_CARDS", config.THREAT_CARDS_CSV)]:
            df = pd.read_csv(path)
            df.columns = [c.upper() for c in df.columns]
            write_pandas(conn, df, name, auto_create_table=True, overwrite=True)
            print(f"Loaded {len(df)} rows into {name}")


if __name__ == "__main__":
    main()

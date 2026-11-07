"""Load the ranked CVEs, threat cards and Granite vectors into Snowflake.

    python -m ai.snowflake_load

Creates in DATATHON.COPILOT (run ai/snowflake_setup.sql once first):
  CVE_CARDS                     500 cards + VECTOR(FLOAT, 384) of Granite embeddings
  VULNERABILITY_PRIORITY_INDEX  view: CVE_ID, RANK, PREDICTED_RISK_SCORE, GRANITE_EXPLANATION,
                                IBM_XFORCE_URL, RAW_DESCRIPTION
  TOP500, THREAT_CARDS          the two contract files, as plain tables

Trial accounts block Cortex AI functions (EMBED_TEXT, AI_COMPLETE), so vectors come from
IBM Granite and search uses the native VECTOR type with VECTOR_COSINE_SIMILARITY.
"""
import json

import pandas as pd

from ai.common import CVE_CARDS_CSV, connect, load_embedder
from shared import config


def main() -> None:
    from snowflake.connector.pandas_tools import write_pandas

    df = pd.read_csv(CVE_CARDS_CSV)
    df["REFERENCE_URLS"] = df.REFERENCE_URLS.fillna("")
    df["IBM_XFORCE_URL"] = df.IBM_XFORCE_URL.fillna("").astype(str)
    df["PREDICTED_RISK_SCORE"] = pd.to_numeric(df.PREDICTED_RISK_SCORE, errors="coerce").astype(float)

    vecs = load_embedder().encode(df.SEARCH_TEXT.fillna("").tolist(), batch_size=64, normalize_embeddings=True)
    dim = vecs.shape[1]
    df["EMB_JSON"] = [json.dumps([round(float(x), 6) for x in v]) for v in vecs]

    with connect() as conn:
        write_pandas(conn, df, "CVE_CARDS_RAW", auto_create_table=True, overwrite=True, quote_identifiers=False)
        cur = conn.cursor()
        cur.execute(f"""
            CREATE OR REPLACE TABLE CVE_CARDS AS
            SELECT * EXCLUDE (EMB_JSON), PARSE_JSON(EMB_JSON)::ARRAY::VECTOR(FLOAT, {dim}) AS EMB
            FROM CVE_CARDS_RAW""")
        cur.execute("DROP TABLE CVE_CARDS_RAW")
        cur.execute("""
            CREATE OR REPLACE VIEW VULNERABILITY_PRIORITY_INDEX AS
            SELECT CVE_ID, RANK, PREDICTED_RISK_SCORE,
                   THREAT_SUMMARY || ' ' || WEAPONIZATION_RISK || ' ' || MITIGATION AS GRANITE_EXPLANATION,
                   IBM_XFORCE_URL, DESCRIPTION AS RAW_DESCRIPTION
            FROM CVE_CARDS""")
        print("CVE_CARDS rows:", cur.execute("SELECT COUNT(*) FROM CVE_CARDS").fetchone()[0])

        for name, path in [("TOP500", config.TOP500_CSV), ("THREAT_CARDS", config.THREAT_CARDS_CSV)]:
            if path.exists():
                t = pd.read_csv(path)
                t.columns = [c.upper() for c in t.columns]
                write_pandas(conn, t, name, auto_create_table=True, overwrite=True, quote_identifiers=False)
                print(f"Loaded {len(t)} rows into {name}")

        for obj in ["TABLE CVE_CARDS", "VIEW VULNERABILITY_PRIORITY_INDEX", "TABLE TOP500", "TABLE THREAT_CARDS"]:
            try:
                cur.execute(f"GRANT SELECT ON {obj} TO ROLE COPILOT_READER")
            except Exception:
                pass  # table may not exist if its CSV was missing


if __name__ == "__main__":
    main()

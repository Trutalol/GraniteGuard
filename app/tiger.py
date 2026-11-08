"""Live queries against Tiger Data (TimescaleDB) for the dashboard.

Reads the continuous aggregates built by pipeline/sql/timescale.sql:
  signals_monthly           monthly exploit climate across every tracked CVE
  assigner_signals_monthly  the same, per CVE assigner (the vendor security team that publishes CVEs)
Both are kept up to date by TimescaleDB from the exploit_signals hypertable (6.4M monthly rows).
"""
from __future__ import annotations

import pandas as pd

from shared import config


def available() -> bool:
    return bool(config.env("TIGER_DATABASE_URL"))


def _query(sql: str, params: tuple = ()) -> pd.DataFrame:
    import psycopg
    with psycopg.connect(config.env("TIGER_DATABASE_URL"), connect_timeout=10) as conn, conn.cursor() as cur:
        cur.execute(sql, params)
        cols = [c.name for c in cur.description]
        return pd.DataFrame(cur.fetchall(), columns=cols)


def threat_climate() -> pd.DataFrame:
    df = _query("""SELECT bucket, cves_tracked, avg_epss, cves_with_public_code, cves_in_kev
                   FROM signals_monthly ORDER BY bucket""")
    df["public_code_share"] = df.cves_with_public_code / df.cves_tracked
    return df


def assigner_of(cve_id: str) -> str | None:
    df = _query("SELECT assigner FROM vulnerabilities WHERE cve_id = %s", (cve_id,))
    return None if df.empty else df.assigner.iloc[0]


def vendor_heat(assigner: str) -> pd.DataFrame:
    """Monthly exploit signals for the assigner's earlier CVEs (2024-2025, before any 2026 snapshot)."""
    return _query("""SELECT bucket, cves_tracked, avg_epss, public_code_rate, cves_in_kev
                     FROM assigner_signals_monthly WHERE assigner = %s ORDER BY bucket""", (assigner,))


def timescale_facts() -> dict:
    """Small proof-of-Tiger panel: extension version, hypertable chunks, compressed size."""
    ver = _query("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'")
    ht = _query("""SELECT num_chunks, compression_enabled FROM timescaledb_information.hypertables
                   WHERE hypertable_name = 'exploit_signals'""")
    size = _query("SELECT pg_size_pretty(hypertable_size('exploit_signals')) AS size")
    rows = _query("SELECT count(*) AS n FROM exploit_signals")
    return {"version": None if ver.empty else ver.extversion.iloc[0],
            "chunks": None if ht.empty else int(ht.num_chunks.iloc[0]),
            "compressed": None if ht.empty else bool(ht.compression_enabled.iloc[0]),
            "size": size["size"].iloc[0], "rows": int(rows.n.iloc[0])}

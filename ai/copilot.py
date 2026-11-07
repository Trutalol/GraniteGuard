"""The 'Ask Copilot' backend the dashboard calls.

Person 3 only needs:  from ai.copilot import ask
"""
from shared import config


def ask(cve_id: str, question: str) -> str:
    """Answer an engineer's question about one CVE using Snowflake Cortex."""
    if not config.env("SNOWFLAKE_ACCOUNT"):
        return f"(copilot offline: set Snowflake keys in .env) You asked about {cve_id}: {question}"

    from ai.snowflake_load import connect

    sql = """
        SELECT SNOWFLAKE.CORTEX.COMPLETE(
            %(model)s,
            CONCAT('You are a SOC copilot. CVE context: ', t.DESCRIPTION,
                   ' Threat brief: ', c.WHY_FIX_FIRST,
                   ' Question: ', %(q)s)
        )
        FROM TOP500 t JOIN THREAT_CARDS c ON t.CVE_ID = c.CVE_ID
        WHERE t.CVE_ID = %(cve)s
    """
    with connect() as conn, conn.cursor() as cur:
        cur.execute(sql, {"model": config.env("SNOWFLAKE_CORTEX_MODEL"), "q": question, "cve": cve_id})
        row = cur.fetchone()
    return row[0] if row else f"No data for {cve_id}."

-- Snapshot rows: one row per CVE at the month we predict from, with only what was known then.
--   * 2024-01 .. 2025-11 publishes for training/backtest. Jan-Sep follow the 2026 rule
--     (snapshot = publish month, June uses July); Oct-Dec use the publish month.
--   * dropped if already on KEV by the end of the snapshot month (as the scoreboard does)
--   * kev_date_added is kept only to build labels later; it is never a feature
--   * 2026 rows come straight from scoreboard_2026.csv
DROP TABLE IF EXISTS cohort;
CREATE TABLE cohort AS
WITH base AS (
    SELECT v.cve_id, v.published,
           CASE WHEN extract(month FROM v.published) = 6
                THEN (date_trunc('month', v.published) + interval '1 month')::date
                ELSE date_trunc('month', v.published)::date END AS snapshot_month
    FROM vulnerabilities v
    WHERE v.published >= '2024-01-01' AND v.published < '2025-12-01'
), hist AS (
    SELECT b.*, (b.snapshot_month + interval '1 month - 1 day')::date AS snapshot_end,
           s.epss, coalesce(s.exploitdb,0) exploitdb, coalesce(s.metasploit,0) metasploit,
           coalesce(s.nuclei,0) nuclei, coalesce(s.poc_github,0) poc_github,
           coalesce(s.in_kev,0) sig_in_kev, k.date_added
    FROM base b
    LEFT JOIN exploit_signals s ON s.cve_id = b.cve_id AND s.month = b.snapshot_month
    LEFT JOIN (SELECT cve_id, min(date_added) date_added FROM known_exploited GROUP BY 1) k
           ON k.cve_id = b.cve_id
)
SELECT cve_id, published, snapshot_month, snapshot_end, epss, exploitdb, metasploit, nuclei, poc_github,
       date_added AS kev_date_added, FALSE AS is_2026
FROM hist
WHERE sig_in_kev = 0 AND (date_added IS NULL OR date_added > snapshot_end)
UNION ALL
SELECT cve_id, published, to_date(snapshot_month || '-01', 'YYYY-MM-DD'),
       (to_date(snapshot_month || '-01', 'YYYY-MM-DD') + interval '1 month - 1 day')::date,
       epss, coalesce(exploitdb,0), coalesce(metasploit,0), coalesce(nuclei,0), coalesce(poc_github,0),
       NULL::date, TRUE
FROM scoreboard;
CREATE INDEX ON cohort (cve_id);
ANALYZE cohort;

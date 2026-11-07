-- One row per CVE with time-series features.
WITH s AS (
    SELECT cve_id, month, epss,
           epss - LAG(epss, 1) OVER w AS epss_momentum,
           epss - LAG(epss, 3) OVER w AS epss_velocity_90d
    FROM exploit_signals
    WINDOW w AS (PARTITION BY cve_id ORDER BY month)
),
latest AS (
    SELECT DISTINCT ON (cve_id) * FROM s ORDER BY cve_id, month DESC
),
first_poc AS (
    SELECT cve_id, MIN(month) AS first_poc_month
    FROM exploit_signals
    WHERE has_github_poc OR has_nuclei OR has_metasploit
    GROUP BY cve_id
)
SELECT l.cve_id, l.epss, l.epss_momentum, l.epss_velocity_90d, p.first_poc_month
FROM latest l LEFT JOIN first_poc p USING (cve_id);

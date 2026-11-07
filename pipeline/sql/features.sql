-- Time-series features, all computed "as of" each row's snapshot month.
-- Nothing here reads nvd_status, n_references, n_affected_cpes, cvss3_source, references.csv
-- or affected_products.csv.

-- 1) Monthly time series per assigner (the CNA that published the CVE; known on day one).
DROP TABLE IF EXISTS assigner_month;
CREATE TABLE assigner_month AS
WITH months AS (SELECT generate_series('2015-01-01'::date, '2026-09-01'::date, interval '1 month')::date AS m),
pubs AS (SELECT assigner, date_trunc('month', published)::date m, count(*) n_pub
         FROM vulnerabilities WHERE assigner IS NOT NULL GROUP BY 1, 2),
kevs AS (SELECT v.assigner, date_trunc('month', k.date_added)::date m, count(*) n_kev
         FROM known_exploited k JOIN vulnerabilities v USING (cve_id) GROUP BY 1, 2),
grid AS (SELECT a.assigner, months.m FROM (SELECT DISTINCT assigner FROM pubs) a CROSS JOIN months)
SELECT g.assigner, g.m,
       -- KEV entries added up to and including month m (cumulative)
       sum(coalesce(k.n_kev,0)) OVER w_all  AS kev_cum,
       sum(coalesce(k.n_kev,0)) OVER w_12   AS kev_12m,
       sum(coalesce(p.n_pub,0)) OVER w_all  AS pub_cum,
       sum(coalesce(p.n_pub,0)) OVER w_12   AS pub_12m
FROM grid g LEFT JOIN pubs p USING (assigner, m) LEFT JOIN kevs k USING (assigner, m)
WINDOW w_all AS (PARTITION BY g.assigner ORDER BY g.m ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW),
       w_12  AS (PARTITION BY g.assigner ORDER BY g.m ROWS BETWEEN 11 PRECEDING AND CURRENT ROW);
CREATE INDEX ON assigner_month (assigner, m);

-- 2) Assigner "heat" from the EPSS / exploit-code time series of its older CVEs.
DROP TABLE IF EXISTS assigner_signal_month;
CREATE TABLE assigner_signal_month AS
SELECT v.assigner, s.month AS m,
       avg(s.epss) AS assigner_epss_mean,
       avg(greatest(s.exploitdb, s.metasploit, s.nuclei, s.poc_github)::float) AS assigner_poc_rate
FROM exploit_signals s JOIN vulnerabilities v USING (cve_id)
WHERE v.assigner IS NOT NULL
GROUP BY 1, 2;
CREATE INDEX ON assigner_signal_month (assigner, m);

-- 3) One feature row per snapshot row.
DROP TABLE IF EXISTS snapshot_features;
CREATE TABLE snapshot_features AS
SELECT c.cve_id, c.published, c.snapshot_month, c.snapshot_end, c.is_2026, c.kev_date_added,
       c.epss, c.exploitdb, c.metasploit, c.nuclei, c.poc_github,
       -- EPSS changed its model in March 2025, so also use the within-month percentile
       percent_rank() OVER (PARTITION BY c.snapshot_month ORDER BY coalesce(c.epss, 0)) AS epss_pct,
       (c.snapshot_end - c.published) AS days_observed,
       v.assigner, v.description, v.cwe_ids,
       v.cvss3_score, v.cvss4_score, v.cvss2_score, v.cvss3_vector, v.cvss4_vector,
       v.attack_vector, v.attack_complexity, v.privileges_required, v.user_interaction, v.scope,
       v.confidentiality_impact, v.integrity_impact, v.availability_impact,
       -- assigner history known at the end of the PREVIOUS month
       am.kev_cum  AS assigner_kev_cum,  am.kev_12m AS assigner_kev_12m,
       am.pub_cum  AS assigner_pub_cum,  am.pub_12m AS assigner_pub_12m,
       sig.assigner_epss_mean, sig.assigner_poc_rate
FROM cohort c
JOIN vulnerabilities v USING (cve_id)
LEFT JOIN assigner_month am
       ON am.assigner = v.assigner
      AND am.m = least((c.snapshot_month - interval '1 month')::date, '2025-12-01'::date)
LEFT JOIN LATERAL (
       SELECT assigner_epss_mean, assigner_poc_rate FROM assigner_signal_month a
       WHERE a.assigner = v.assigner AND a.m < c.snapshot_month
       ORDER BY a.m DESC LIMIT 1) sig ON TRUE;

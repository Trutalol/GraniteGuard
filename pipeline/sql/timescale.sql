-- TimescaleDB features on Tiger Data. Run after `python train_and_predict.py` has loaded the data
-- (re-running ingest drops exploit_signals, which also drops these views, so run this again after it).
--   python -m pipeline.timescale_extras     (or paste into the Tiger console SQL editor)

-- 1) Columnstore compression on the 6.4M-row exploit_signals hypertable.
--    Ordering by cve_id, month keeps each CVE's monthly rows together, which compresses well.
ALTER TABLE exploit_signals SET (
  timescaledb.compress,
  timescaledb.compress_orderby = 'cve_id, month'
);
SELECT count(compress_chunk(c, if_not_compressed => true)) AS chunks_compressed
FROM show_chunks('exploit_signals') c;

-- 2) Continuous aggregate: monthly exploit climate across every tracked CVE.
CREATE MATERIALIZED VIEW IF NOT EXISTS signals_monthly
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 month', month) AS bucket,
       count(*)                                                 AS cves_tracked,
       avg(epss)                                                AS avg_epss,
       sum(greatest(exploitdb, metasploit, nuclei, poc_github)) AS cves_with_public_code,
       sum(in_kev)                                              AS cves_in_kev
FROM exploit_signals
GROUP BY bucket
WITH NO DATA;
CALL refresh_continuous_aggregate('signals_monthly', NULL, NULL);

-- 3) Continuous aggregate per assigner (the vendor security team that publishes the CVE).
--    The dashboard shows how the selected CVE's assigner's earlier CVEs were exploited over time.
CREATE MATERIALIZED VIEW IF NOT EXISTS assigner_signals_monthly
WITH (timescaledb.continuous) AS
SELECT time_bucket('1 month', s.month) AS bucket,
       v.assigner,
       count(*)                                                                AS cves_tracked,
       avg(s.epss)                                                             AS avg_epss,
       avg(greatest(s.exploitdb, s.metasploit, s.nuclei, s.poc_github)::float) AS public_code_rate,
       sum(s.in_kev)                                                           AS cves_in_kev
FROM exploit_signals s
JOIN vulnerabilities v ON s.cve_id = v.cve_id
GROUP BY bucket, v.assigner
WITH NO DATA;
CALL refresh_continuous_aggregate('assigner_signals_monthly', NULL, NULL);

SELECT pg_size_pretty(hypertable_size('exploit_signals')) AS exploit_signals_size;

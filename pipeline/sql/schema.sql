-- Schema for the CVE triage pipeline. Runs on Tiger Data (TimescaleDB) or plain PostgreSQL 16.
-- If the timescaledb extension is available, exploit_signals becomes a hypertable on month.
DROP TABLE IF EXISTS exploit_signals, vulnerabilities, known_exploited, scoreboard CASCADE;

CREATE TABLE exploit_signals (
    month       DATE NOT NULL,        -- first day of the month (values are end-of-month)
    cve_id      TEXT NOT NULL,
    epss        DOUBLE PRECISION,
    in_kev      SMALLINT,
    exploitdb   SMALLINT,
    metasploit  SMALLINT,
    nuclei      SMALLINT,
    poc_github  SMALLINT
);

CREATE TABLE vulnerabilities (
    cve_id TEXT PRIMARY KEY, published DATE, last_modified DATE, nvd_status TEXT, assigner TEXT,
    description TEXT, cvss3_version TEXT, cvss3_score REAL, cvss3_severity TEXT, cvss3_vector TEXT,
    attack_vector TEXT, attack_complexity TEXT, privileges_required TEXT, user_interaction TEXT,
    scope TEXT, confidentiality_impact TEXT, integrity_impact TEXT, availability_impact TEXT,
    cvss3_exploitability_score REAL, cvss3_impact_score REAL, cvss3_source TEXT,
    cvss4_score REAL, cvss4_severity TEXT, cvss4_vector TEXT,
    cvss2_score REAL, cvss2_severity TEXT, cvss2_vector TEXT,
    cwe_ids TEXT, n_references INT, n_affected_cpes INT
);

CREATE TABLE known_exploited (
    cve_id TEXT, vendor TEXT, product TEXT, name TEXT, date_added DATE, short_description TEXT,
    required_action TEXT, due_date DATE, known_ransomware_use TEXT, cwe_ids TEXT
);

CREATE TABLE scoreboard (
    cve_id TEXT PRIMARY KEY, published DATE, snapshot_month TEXT, epss DOUBLE PRECISION,
    exploitdb SMALLINT, metasploit SMALLINT, nuclei SMALLINT, poc_github SMALLINT
);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb') THEN
        CREATE EXTENSION IF NOT EXISTS timescaledb;
        PERFORM create_hypertable('exploit_signals', 'month');
    ELSE
        RAISE NOTICE 'timescaledb not available: using a plain PostgreSQL table';
    END IF;
END $$;

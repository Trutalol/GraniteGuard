-- Tiger Data (TimescaleDB) table for monthly exploit signals.
-- Adjust the columns to match the real CSV headers.
CREATE TABLE IF NOT EXISTS exploit_signals (
    month          DATE        NOT NULL,
    cve_id         TEXT        NOT NULL,
    epss           DOUBLE PRECISION,
    has_github_poc BOOLEAN,
    has_nuclei     BOOLEAN,
    has_metasploit BOOLEAN
);
SELECT create_hypertable('exploit_signals', 'month', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_signals_cve ON exploit_signals (cve_id, month DESC);

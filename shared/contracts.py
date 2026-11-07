"""The agreements between the three parts of the project.

Every handoff file must have exactly these columns. Change this file only after telling the team.
"""

# Person 1 -> everyone: the ranked list
TOP500_COLUMNS = [
    "rank",            # 1..500, 1 = fix first
    "cve_id",          # e.g. CVE-2025-1234
    "score",           # model score, higher = more likely weaponized
    "cvss",            # baseline, for the "we beat CVSS" comparison
    "epss",            # latest EPSS, baseline for comparison
    "epss_momentum",   # EPSS_t - EPSS_t-1
    "poc_lag_days",    # days from CVE publish to first public PoC (blank if none)
    "published_date",  # YYYY-MM-DD
    "description",     # CVE text, used by Person 2 for Granite
]

# Person 1 -> Person 3: monthly EPSS trajectory for the charts
EPSS_HISTORY_COLUMNS = [
    "cve_id",
    "month",           # YYYY-MM-01
    "epss",
]

# Person 2 -> Person 3: Granite threat cards
THREAT_CARDS_COLUMNS = [
    "cve_id",
    "attack_surface",  # short tags, e.g. "remote; pre-auth; RCE"
    "why_fix_first",   # 2-4 sentence Granite Instruct brief
]

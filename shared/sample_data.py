"""Write fake handoff files so nobody has to wait on anybody.

    python -m shared.sample_data
"""
import numpy as np
import pandas as pd

from shared import config
from shared.contracts import EPSS_HISTORY_COLUMNS, THREAT_CARDS_COLUMNS, TOP500_COLUMNS

N = 500


def main() -> None:
    rng = np.random.default_rng(42)
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    cves = [f"CVE-2025-{10000 + i}" for i in range(N)]

    top = pd.DataFrame({
        "rank": range(1, N + 1),
        "cve_id": cves,
        "score": np.sort(rng.random(N))[::-1].round(4),
        "cvss": rng.uniform(3, 10, N).round(1),
        "epss": rng.random(N).round(4),
        "epss_momentum": rng.normal(0, 0.05, N).round(4),
        "poc_lag_days": rng.integers(0, 120, N),
        "published_date": pd.Timestamp("2025-01-01") + pd.to_timedelta(rng.integers(0, 300, N), unit="D"),
        "description": ["Sample description: remote attacker can execute code via crafted request."] * N,
    })[TOP500_COLUMNS]
    top["published_date"] = top["published_date"].dt.strftime("%Y-%m-%d")
    top.to_csv(config.TOP500_CSV, index=False)

    months = pd.date_range("2024-01-01", "2025-12-01", freq="MS")
    hist = pd.DataFrame(
        [(c, m.strftime("%Y-%m-%d"), float(np.clip(rng.random() * (i + 1) / len(months), 0, 1)))
         for c in cves[:50] for i, m in enumerate(months)],
        columns=EPSS_HISTORY_COLUMNS,
    )
    hist.to_csv(config.EPSS_HISTORY_CSV, index=False)

    cards = pd.DataFrame({
        "cve_id": cves,
        "attack_surface": "remote; pre-auth; RCE",
        "why_fix_first": "Sample brief: EPSS is climbing fast and a public PoC appeared within days.",
    })[THREAT_CARDS_COLUMNS]
    cards.to_csv(config.THREAT_CARDS_CSV, index=False)

    print(f"Wrote sample files to {config.PROCESSED_DIR}")


if __name__ == "__main__":
    main()

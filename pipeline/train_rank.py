"""Train the ranking model and write the handoff files."""
import pandas as pd

from shared import config
from shared.contracts import TOP500_COLUMNS


def main() -> None:
    features = pd.read_csv(config.PROCESSED_DIR / "features.csv")
    # TODO: join CVE metadata (cvss, description, published_date) and labels,
    #       train lightgbm.LGBMRanker / LGBMClassifier, then score every CVE.
    features["score"] = features["epss"].fillna(0)  # placeholder until the model exists

    top = features.sort_values("score", ascending=False).head(500).reset_index(drop=True)
    top["rank"] = top.index + 1
    for col in TOP500_COLUMNS:
        top.setdefault(col, None)
    top[TOP500_COLUMNS].to_csv(config.TOP500_CSV, index=False)
    # TODO: also write config.EPSS_HISTORY_CSV for these 500 CVEs
    print(f"Wrote {config.TOP500_CSV}")


if __name__ == "__main__":
    main()

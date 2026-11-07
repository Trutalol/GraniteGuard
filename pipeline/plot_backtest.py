"""Chart: how many later-exploited CVEs each ranking finds, on our leakage-free backtests.

Left: the 2025 mirror of the benchmark (top 243 of 35,277 = same share as 500 of 72,670).
Right: total over 5 quarterly rolling tests (2024-07 .. 2025-07), see docs/backtest_folds.md.
Writes docs/backtest_hits.png
"""
import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from shared import config

# Totals from the 5 rolling tests (docs/backtest_folds.md); 94 exploited CVEs in all.
FOLD_TOTALS = {"Highest CVSS 3 first": None, "EPSS first": None,
               "Public exploit, then EPSS": 20, "Our ensemble": 31}
NAMES = {"cvss3_first": "Highest CVSS 3 first", "epss_first": "EPSS first",
         "public_exploit_then_epss": "Public exploit, then EPSS", "ensemble": "Our ensemble"}
ACCENT, NEUTRAL, INK, MUTED, SURFACE = "#2a78d6", "#b9b7b0", "#0b0b0b", "#52514e", "#fcfcfb"


def panel(ax, values: dict, title: str, total: int):
    labels = [k for k in values if values[k] is not None]
    vals = [values[k] for k in labels]
    colors = [ACCENT if k == "Our ensemble" else NEUTRAL for k in labels]
    ax.barh(labels, vals, color=colors, height=0.55)
    for y, v in enumerate(vals):
        ax.text(v + total * 0.012, y, str(v), va="center", color=INK, fontsize=11)
    ax.set_xlim(0, max(vals) * 1.25)
    ax.invert_yaxis()
    ax.set_title(title, loc="left", color=INK, fontsize=12, pad=10)
    ax.set_facecolor(SURFACE)
    for s in ["top", "right", "left"]:
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color("#d8d6cf")
    ax.tick_params(colors=MUTED, length=0)
    ax.grid(axis="x", color="#ebe9e3", linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_xlabel(f"Exploited CVEs found (of {total})", color=MUTED)


def main() -> None:
    m = json.loads((config.PROCESSED_DIR / "backtest_metrics.json").read_text())
    k = m["k_scaled_equivalent_of_top500"]
    mirror = {NAMES[n]: m[f"hits_at_{k}"][n] for n in NAMES}
    fig, axes = plt.subplots(1, 2, figsize=(12, 3.8), facecolor=SURFACE)
    panel(axes[0], mirror, f"2025 replay of the benchmark (top {k} of {m['test_rows']:,})", m["test_positives"])
    panel(axes[1], FOLD_TOTALS, "5 rolling quarterly tests, 2024–2025 (top 0.69% each)", 94)
    fig.suptitle("Which ranking finds the CVEs attackers exploit next?", x=0.01, ha="left",
                 color=INK, fontsize=14, fontweight="bold")
    fig.text(0.01, -0.02, "Trained only on what was known before each test period. Right panel: CVSS/EPSS-only "
             "baselines were not re-run per fold.", color=MUTED, fontsize=9)
    fig.tight_layout()
    out = config.ROOT / "docs" / "backtest_hits.png"
    fig.savefig(out, dpi=200, bbox_inches="tight", facecolor=SURFACE)
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()

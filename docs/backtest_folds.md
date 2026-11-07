# Rolling backtests and what did not help

Each fold pretends it is the first day of a quarter. The model trains only on snapshot rows before
that date, with KEV entries known before that date. It then ranks the new CVEs published in the
next three months and counts hits in the top 0.69% (the same share as 500 of the 72,670 2026 rows).
Labels: added to KEV within 310 days, up to 2025-12-31.

| Fold start | New CVEs | Later on KEV | Top k | PoC then EPSS | Ensemble |
|---|---|---|---|---|---|
| 2024-07 | 11,570 | 24 | 80 | 4 | 7 |
| 2024-10 | 11,029 | 21 | 76 | 3 | 4 |
| 2025-01 | 11,913 | 20 | 82 | 4 | 7 |
| 2025-04 | 7,991 | 11 | 55 | 6 | 6 |
| 2025-07 | 15,373 | 18 | 106 | 3 | 7 |
| **Total** | | **94** | | **20** | **31** |
| 2025 mirror of the benchmark | 35,277 | 45 | 243 | 14 | 17 |

The ensemble beats the best simple rule in 4 of 5 folds and ties in the fifth.

## Tried and not adopted (no gain on these folds)

| Idea | Folds total | 2025 mirror |
|---|---|---|
| Current ensemble | 31 | 17 |
| + 134k older-CVE rows (published 2019+, re-seen each month), weight 0.3 / 1.0 | 32 / 31 | 14 / 14 |
| + IBM Granite embedding similarity to past KEV descriptions (granite-embedding-30m-english) | 31 | 17 |
| Granite embedding classifier blended into the text score | 27 | 17 |
| Granite classifier as an extra ranked vote | 21 | 11 |

The positives are scarce (11 to 24 per fold), so a difference of 1 or 2 hits is noise. We kept
the simpler model. The Granite embeddings (`ai/granite_embed_cves.py`) are still useful for the
similar-CVE search and briefs in `ai/`.

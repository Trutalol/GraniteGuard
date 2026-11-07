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
| + sibling-CVE features (same assigner, ±7 days, Granite similarity ≥ 0.85) | 32 | 15 |
| + assigner→KEV-vendor history (fixes Fortinet/SonicWall/Zyxel matching) | 32 | 16 |
| Both of the above | 31 | 15 |
| Share scores between near-identical siblings (similarity ≥ 0.9 / 0.95) | 30–31 | 17 |

The positives are scarce (11 to 24 per fold), so a difference of 1 or 2 hits is noise. We kept
the simpler model. The Granite embeddings (`ai/granite_embed_cves.py`) are still useful for the
similar-CVE search and briefs in `ai/`.

## Data cleaning checks

| Issue found | Fix tried | 5 tests | 2025 replay |
|---|---|---|---|
| (none) current model | | 31 | 17 |
| No signal row at the snapshot for 45% of Jan 2025 and 23% of Feb 2025 new CVEs (vs 2% in 2026), so they look like "no exploit evidence" | Drop those rows from training only | 31 | 14 |
| EPSS changed models in March 2025, so raw scores before and after differ | Use only the within-month EPSS percentile | 32 | 17 |
| KEV vendor names changed after acquisitions (Pulse Secure→Ivanti, VMware Tanzu/Broadcom→VMware, Micro Focus→OpenText) | Merge the names before counting vendor history | 31 | 17 |
| All three together | | 30 | 16 |

Already handled by the design: rejected IDs in the signals files never enter (rows come from
`vulnerabilities.csv`); the 62 KEV entries dated before publish are dropped, because they are on
KEV at their snapshot; the CVE year is ignored in favour of `published`. 148 snapshot rows say
"DISPUTED" and were left in.

## More ideas tested (no gain)

| Idea | 5 tests | 2025 replay |
|---|---|---|
| Current model | 31 | 17 |
| Learning-to-rank (LambdaRank) added to the ensemble | 32 | 16 |
| Recent 6 months weighted ×3 | 31 | 15 |
| Weakness-type families (RCE-type, auth-bypass-type CWEs) | 31 | 17 |
| Remote + no privileges + no user action, edge-device / auth-bypass keywords | 28 | 15 |
| Microsoft Patch Tuesday "Exploitation More Likely" (api.msrc.microsoft.com, 2024–2026) | 31 | 17 |
| ...plus Microsoft "Publicly Disclosed" | 30 | 16 |

Microsoft's "Exploitation Detected" / "Exploited: Yes" was **not** used: Microsoft updates it after
attacks are seen, and 3 of the 5 snapshot rows carrying it were later added to KEV, so it leaks.
| EPSS / exploit-code rate relative to CVEs of the same age in the same month | 33 | 16 |
| Each snapshot month gets its share of the top slots | 29 | 19 |
| Both together | 33 | 17 |

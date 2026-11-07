# Columns used by the ranking model (for the write-up)

**Rule:** every feature for a row is what was known at the end of that row's `snapshot_month`.
Training rows are 2024 and 2025 CVEs built with the same rules as `scoreboard_2026.csv`
(snapshot = publish month, June uses July, drop CVEs already on KEV by the snapshot).

## Used

| Source | Columns | How |
|---|---|---|
| `exploit_signals_2024/2025.csv` (training) and `scoreboard_2026.csv` (2026) | `epss`, `exploitdb`, `metasploit`, `nuclei`, `poc_github` | Value at the snapshot month only. Also the EPSS percentile within the snapshot month, because EPSS changed models in March 2025. |
| `exploit_signals_*.csv` | `epss`, exploit flags of the assigner's *older* CVEs | Assigner "heat": mean EPSS and exploit-code rate in the latest month before the snapshot (computed, dropped from the final trees; kept in the SQL). |
| `vulnerabilities.csv` | `published` | Days between publish and end of snapshot month. |
| `vulnerabilities.csv` | `description` | TF-IDF text prior; KEV vendor/product names found in the text; a few keyword flags. |
| `vulnerabilities.csv` | `assigner` | As-of KEV rate of the CNA: KEV entries for its CVEs added before the snapshot month, divided by its CVE count. |
| `vulnerabilities.csv` | `cwe_ids`, `attack_vector`, `attack_complexity`, `privileges_required`, `user_interaction`, `scope` | Tokens in the text prior only when present; blanks add nothing. |
| `known_exploited.csv` | `cve_id`, `vendor`, `product`, `date_added` | Labels, and as-of counts that only use entries added **before** the snapshot month. |

## Not used (leak or availability risk for 2026)

- `nvd_status`, `n_references`, `n_affected_cpes`, `cvss3_source`, `last_modified`
- `references.csv` (news / threat-report links get added after attacks)
- `affected_products.csv` (most 2026 CVEs are unanalysed, so a product list itself signals review)
- Blank vs filled CVSS: missing scores are imputed with the 2024-25 median/mode and there is no
  "missing" flag. `cvss3_score` appears in `top500.csv` only as a comparison column.
- No EPSS history for 2026: the scoreboard gives one month per CVE, so `epss_momentum` is blank.

## Labels

- Training (final model): CVE added to KEV after its snapshot, within 310 days, using KEV entries up
  to 2025-12-31 only. 82,424 rows, 112 positives.
- Backtest: train as if on 2025-01-01 (2024 snapshots, KEV to 2024-12-31), then rank CVEs
  published Jan-Sep 2025 with label "added to KEV by 2025-11-04", the 2026 judging rule one year earlier.

## Residual risks

- Descriptions are today's version. A few CVE descriptions say "exploited in the wild"; only 17 of the
  72,670 scoreboard CVEs (and 2 of our top 500) contain such a phrase.
- Our top 500 is 49% `Analyzed` vs 43% for the whole scoreboard, and 6.8% blank CVSS vs 8.7%.
  The model never sees status, so this mild tilt comes through severity/text.
- Hyperparameters and the ensemble were chosen on the one 2025 backtest (45 positives), so the
  backtest number is slightly optimistic.

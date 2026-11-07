# GraniteGuard — Fix this first

Draft for Devpost. Replace bracketed items with verified evidence before publishing.

## Inspiration
Security teams need to decide what to patch with limited engineering time. Severity describes potential damage, but does not by itself establish whether attackers will exploit a vulnerability. We built GraniteGuard to turn exploitation signals into a focused review queue with explanations engineers can inspect.

## What it does
GraniteGuard presents a ranked vulnerability queue, monthly EPSS history, and threat briefs through a Streamlit dashboard. Engineers can search CVEs, set a review budget, inspect a vulnerability, and ask a configured Snowflake Copilot for context. The submission download produces the required single cve_id column after checking 500 unique IDs against the supplied scoreboard. Synthetic demonstrations are clearly labelled.

## How we built it
- Person 1 owns Tiger Data/Postgres ingestion, historical features, LightGBM ranking, and evaluation. The dashboard consumes exported CSVs; it does not query Tiger Data directly.
- Person 2 owns IBM Granite embeddings and explanatory briefs, plus the Snowflake backend. Record the exact Granite embedding and instruct model IDs, inference provider, and one verified generation here: [ADD EVIDENCE]. IBM use must be demonstrated with a real run, not sample briefs.
- Person 3 built the Streamlit workflow, Plotly history charts, submission export, and presentation materials.
- The current Copilot implementation calls Snowflake Cortex through the Python connector and joins descriptions with threat cards. A REST endpoint and retrieval with source citations remain planned until implemented and tested. Do not claim verified RAG or supported mitigation citations yet.

## Data use and leakage controls
The challenge provides vulnerability metadata, monthly exploitation signals, historical KEV labels, CWE definitions, and a 2026 scoreboard. The benchmark requires using only information available at the end of each CVE's snapshot_month. Use publication dates rather than the year embedded in CVE IDs. The supplied historical KEV file ends in 2025; it cannot establish the judges' 2026 outcomes.

Final model inputs: [PERSON 1: LIST EXACT COLUMNS, TRANSFORMATIONS, AND TIMESTAMP RULES]. Dashboard display columns are not necessarily model features. Current NIST descriptions and severity fields may have changed after the prediction cutoff; their historical availability must be established. NIST status, product/reference counts, score missingness, and later news or research references can leak outcomes. Audit description embeddings too. Handle the March 2025 EPSS model change and missing historical observations explicitly.

Our shared ranking/history contract does not yet carry snapshot_month or provenance. The team must document or extend that handoff before claiming a cutoff-safe pipeline. KEV absence means no catalog confirmation, not proof that exploitation never occurred.

## Results
Results are pending; synthetic data is not evaluation evidence.

| Evaluation | Model | CVSS baseline | EPSS baseline |
|---|---|---|---|
| Hits among top 500 | [pending] | [pending] | [pending] |
| Precision at 500 | [pending] | [pending] | [pending] |

Report the same candidate population, prediction dates, outcome horizon, tie handling, missing-value treatment, and temporal holdout for all methods. Precision at 500 equals hits divided by 500. Include a signal ablation to support the discovery claim: [WHAT HELPED BEYOND EPSS ALONE?]. Do not extrapolate benchmark results to guaranteed prevention of attacks.

## Challenges and accomplishments
We separated internal dashboard data from the judge submission format, supported missing teammate handoffs, and made synthetic versus real evidence visible. The central modeling challenge is temporal leakage, not merely choosing a classifier. The central product challenge is making prioritization inspectable without presenting generated text as verified security advice.

## What's next
Validate the complete pipeline, add source-grounded mitigation retrieval, capture feature provenance, and incorporate an organization's asset exposure and patch constraints.

## Submission links
- Repository: [ADD URL]
- 2–3 minute demo: [ADD URL]
- top500.csv: [ATTACH VALIDATED EXPORT]
- Organizer dataset/source page: [ADD EXACT PROVIDED URL]
- Outside data: [LIST ACTUAL URLS AND DATES, OR STATE NONE]
- IBM model artifacts and run evidence: [ADD EXACT MODEL URLS AND IDS]

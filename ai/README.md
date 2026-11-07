# ai/ (Person 2: AI & Cloud Lead)

**You read:** `data/processed/top500.csv`
**You produce:** `data/processed/threat_cards.csv` and the Snowflake tables the copilot uses.
**Person 3 calls:** `ai.copilot.ask(cve_id, question)` from the dashboard.

Run order:
1. `python -m ai.granite_embed` embeds CVE descriptions
2. `python -m ai.granite_briefs` writes "why fix this first" threat cards
3. `python -m ai.snowflake_load` loads top500 + threat cards + references into Snowflake

TODO
- [ ] Granite embeddings (also hand them to Person 1 as model features)
- [ ] Granite Instruct briefs for all 500
- [ ] Load tables into Snowflake
- [ ] Cortex `COMPLETE` copilot via the Snowflake REST/SQL API

# app/ (Person 3: Product & Pitch Lead)

**You read:** `top500.csv`, `epss_history.csv`, `threat_cards.csv`, and `ai.copilot.ask`.

```bash
python -m shared.sample_data   # fake data until the real files exist
streamlit run app/streamlit_app.py
```

TODO
- [ ] Ranked table with CVSS/EPSS baseline comparison
- [ ] EPSS trajectory chart from Tiger Data
- [ ] Granite threat card per CVE
- [ ] Copilot chat drawer
- [ ] Devpost write-up (`docs/devpost.md`) and demo script (`docs/demo_script.md`)

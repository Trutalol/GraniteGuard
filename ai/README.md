# ai/ (Person 2: AI & Cloud Lead)

**You read:** `data/processed/top500.csv` (falls back to `submission/top500_detailed.csv`)
**You produce:**
- `data/processed/threat_cards.csv`: the contract file (`cve_id`, `attack_surface`, `why_fix_first`)
- `data/processed/granite_explanations.json`: full cards (threat, weaponization, mitigation, products, X-Force and reference links)
- `data/processed/granite_features.parquet`: Granite text features for Person 1
- Snowflake tables `CVE_CARDS` (with Granite vectors), `TOP500`, `THREAT_CARDS` and the view `VULNERABILITY_PRIORITY_INDEX`

**Person 3 calls:** `ai.copilot.ask(cve_id, question)` (returns text) or `ai.copilot.ask_full(question)` (returns answer + sources).

## How it works

```
question ─► Granite embedding ─► Snowflake SQL REST API (vector search, read-only user)
                                        │
                                  top 5 cards
                                        ▼
                          Granite Instruct ─► answer + sources ─► dashboard
```

| IBM model | Used for |
|---|---|
| `ibm-granite/granite-embedding-30m-english` | Description embeddings (features for Person 1), card vectors, question vectors |
| `ibm-granite/granite-3.3-2b-instruct` | Threat cards and Copilot answers |

Snowflake trial accounts block Cortex AI functions (Cortex Search, `EMBED_TEXT`, `AI_COMPLETE`), so we embed with Granite, store vectors in a native `VECTOR(FLOAT, 384)` column and search with `VECTOR_COSINE_SIMILARITY` through the Snowflake SQL REST API (`/api/v2/statements`, key-pair JWT). All AI stays on IBM Granite.

## Run order (on a GPU, e.g. Colab T4)

One-time: run `ai/snowflake_setup.sql` in a Snowsight worksheet, make the two key pairs (below) and fill the Person 2 part of `.env`.

```bash
python -m ai.granite_embed              # Granite embeddings + granite_features.parquet
python -m ai.granite_briefs --limit 5   # test a few cards first
python -m ai.granite_briefs             # all 500 cards
python -m ai.snowflake_load             # cards + vectors into Snowflake
python -m ai.serve                      # prints COPILOT_URL and COPILOT_KEY
```

Put the printed `COPILOT_URL` and `COPILOT_KEY` in the dashboard machine's `.env`. The URL only works while `ai.serve` is running; a restart gives a new URL.

Key pair for a service user (save the `.p8` under `keys/`, which is gitignored):

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
open("keys/copilot_app_key.p8", "wb").write(key.private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
pub = key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode()
print("".join(pub.splitlines()[1:-1]))   # paste into ALTER USER ... SET RSA_PUBLIC_KEY
```

## Copilot API

| Endpoint | Returns |
|---|---|
| `GET /health` | `{"ok": true}` |
| `POST /ask` with `{"question": "..."}` | `{"answer", "sources": [{cve_id, rank, score, ibm_xforce_url, reference_urls}], "unverified_citations"}` |
| `GET /card/{cve_id}` | One card from Snowflake, or 404 if not in the top 500 |

All except `/health` need the header `x-api-key`.

## Keeping it grounded

- Card prompts contain only facts from the data and forbid inventing versions, vendors or attacks. Output must be JSON with three fields; malformed outputs are retried.
- `attack_surface` tags come from the data (attack vector, privileges, exploit flags), not the LLM.
- Copilot answers use only the retrieved cards. Invented links are stripped, and every cited CVE ID is checked against the retrieved sources (`unverified_citations` should be empty).
- Exploit-code questions filter to cards with public exploit code; "what first" questions sort the retrieved cards by our model's rank.
- User questions go to Snowflake only as bound parameters, never pasted into SQL.

## Columns used (fairness)

**Text features:** `description` and `published` from `vulnerabilities.csv` only. PCA is fit on pre-2026 CVEs. No `nvd_status`, `n_affected_cpes`, `n_references` or `references.csv`.

**Threat cards (explanation only, not ranking):** CVSS fields and `cwe_ids` from `vulnerabilities.csv`, EPSS and exploit flags at `snapshot_month` from `scoreboard_2026.csv`, product names from `affected_products.csv`, and links (including IBM X-Force Exchange) from `references.csv`. Products, links and some CVSS fields are today's NIST data and may have been filled in after attacks, so they are shown to engineers but never fed to the ranking model.

## Limitations

- The 2B Granite model sometimes leaves out one of several matching cards; the sources list always shows all of them in rank order.
- Keyword flags are simple regex matches and miss some phrasings.

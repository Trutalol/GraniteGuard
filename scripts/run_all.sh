#!/usr/bin/env bash
# Runs the whole pipeline in order. Stops at the first failure.
set -euo pipefail
cd "$(dirname "$0")/.."

python -m pipeline.ingest_tiger
python -m pipeline.features
python -m pipeline.train_rank
python -m ai.granite_embed
python -m ai.granite_briefs
python -m ai.snowflake_load
pytest -q
streamlit run app/streamlit_app.py

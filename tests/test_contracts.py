"""Check every handoff file matches shared/contracts.py. Runs on sample data if needed."""
import pandas as pd
import pytest

from shared import config, sample_data
from shared.contracts import EPSS_HISTORY_COLUMNS, THREAT_CARDS_COLUMNS, TOP500_COLUMNS


@pytest.fixture(scope="session", autouse=True)
def ensure_files():
    if not config.TOP500_CSV.exists():
        sample_data.main()


@pytest.mark.parametrize("path,cols", [
    (config.TOP500_CSV, TOP500_COLUMNS),
    (config.EPSS_HISTORY_CSV, EPSS_HISTORY_COLUMNS),
    (config.THREAT_CARDS_CSV, THREAT_CARDS_COLUMNS),
])
def test_columns_match_contract(path, cols):
    if not path.exists():
        pytest.skip(f"{path.name} not produced yet")
    assert list(pd.read_csv(path, nrows=1).columns) == cols


def test_top500_is_ranked():
    top = pd.read_csv(config.TOP500_CSV)
    assert len(top) <= 500
    assert top["rank"].tolist() == list(range(1, len(top) + 1))
    assert top["cve_id"].is_unique

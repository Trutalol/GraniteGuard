"""Settings and file paths everyone uses. Read keys from .env, never hard-code them."""
import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"

# Handoff files (see contracts.py for their columns)
TOP500_CSV = PROCESSED_DIR / "top500.csv"
EPSS_HISTORY_CSV = PROCESSED_DIR / "epss_history.csv"
THREAT_CARDS_CSV = PROCESSED_DIR / "threat_cards.csv"


def env(name: str, default: str | None = None) -> str | None:
    return os.getenv(name, default)

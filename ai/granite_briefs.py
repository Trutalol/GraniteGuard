"""Generate 'why fix this first' threat cards with Granite Instruct."""
import pandas as pd

from shared import config
from shared.contracts import THREAT_CARDS_COLUMNS

PROMPT = """You are a security analyst. In 2-4 sentences, explain why an engineer
should patch {cve_id} first. Use the facts below and be concrete.

Description: {description}
CVSS: {cvss}  EPSS: {epss}  EPSS change this month: {epss_momentum}
Days from publish to public exploit: {poc_lag_days}
"""


def generate(prompt: str) -> str:
    # TODO: call Granite Instruct (watsonx.ai ModelInference or a Hugging Face pipeline).
    return "TODO: Granite brief"


def main() -> None:
    top = pd.read_csv(config.TOP500_CSV)
    rows = []
    for r in top.to_dict("records"):
        rows.append({
            "cve_id": r["cve_id"],
            "attack_surface": "TODO",
            "why_fix_first": generate(PROMPT.format(**r)),
        })
    pd.DataFrame(rows, columns=THREAT_CARDS_COLUMNS).to_csv(config.THREAT_CARDS_CSV, index=False)
    print(f"Wrote {config.THREAT_CARDS_CSV}")


if __name__ == "__main__":
    main()

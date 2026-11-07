"""Generate 'why fix this first' threat cards with IBM Granite Instruct.

    python -m ai.granite_briefs             # all 500
    python -m ai.granite_briefs --limit 5   # quick test

Reads Person 1's top500.csv (data/processed/, or submission/top500_detailed.csv as a fallback).
Writes:
  data/processed/threat_cards.csv          the contract file the dashboard reads
                                           (cve_id, attack_surface, why_fix_first)
  data/processed/granite_explanations.json full cards: threat_summary, weaponization_risk,
                                           mitigation, products, X-Force + reference links
  data/processed/cve_cards.csv             the same cards, flattened for ai.snowflake_load
"""
import argparse
import json
import re

import pandas as pd

from ai.common import CVE_CARDS_CSV, EXPLANATIONS_JSON, EXPLOIT_FLAGS, RAW_DIR, Granite
from shared import config
from shared.contracts import THREAT_CARDS_COLUMNS

CARD_KEYS = ["threat_summary", "weaponization_risk", "mitigation"]
FALLBACK_TOP500 = config.ROOT / "submission" / "top500_detailed.csv"

SYSTEM = ("You are a vulnerability analyst writing for security engineers. "
          "Use ONLY the facts provided. Do not invent versions, vendors, attackers or events. "
          "Reply with a single JSON object and nothing else.")


def load_top500() -> pd.DataFrame:
    path = config.TOP500_CSV if config.TOP500_CSV.exists() else FALLBACK_TOP500
    print(f"Reading {path}")
    return pd.read_csv(path)


def build_profiles(top: pd.DataFrame) -> pd.DataFrame:
    """Add the facts a card needs. Products and references are display-only, never ranking inputs."""
    ids = set(top.cve_id)
    v = pd.read_csv(RAW_DIR / "vulnerabilities.csv",
                    usecols=["cve_id", "published", "cvss3_severity", "attack_vector",
                             "privileges_required", "user_interaction", "cwe_ids"])
    v = v[v.cve_id.isin(ids)]
    cwe = pd.read_csv(RAW_DIR / "weakness_types.csv", usecols=["cwe_id", "name"]).set_index("cwe_id")["name"]
    v["weakness"] = v.cwe_ids.apply(
        lambda s: "unknown" if pd.isna(s) else "; ".join(cwe.get(c, c) for c in s.split(";")))

    sb = pd.read_csv(RAW_DIR / "scoreboard_2026.csv", usecols=["cve_id"] + EXPLOIT_FLAGS)

    ap = pd.read_csv(RAW_DIR / "affected_products.csv",
                     usecols=["cve_id", "vendor", "product", "vulnerable"], dtype=str)
    ap = ap[ap.cve_id.isin(ids) & (ap.vulnerable == "Y")]
    # ap["product"], not ap.product: DataFrame.product is a pandas method
    prods = (ap.assign(p=ap["vendor"] + " " + ap["product"])
               .groupby("cve_id")["p"].apply(lambda s: ", ".join(s.unique()[:5])))

    refs = pd.read_csv(RAW_DIR / "references.csv", usecols=["cve_id", "url", "domain"])
    refs = refs[refs.cve_id.isin(ids)]
    ref_urls = refs.groupby("cve_id").url.apply(lambda s: list(s)[:5])
    xforce = refs[refs.domain.fillna("").str.contains("xforce")].groupby("cve_id").url.first()

    prof = (top.drop(columns=[c for c in ["published"] if c in top.columns])
               .merge(v, on="cve_id", how="left").merge(sb, on="cve_id", how="left"))
    prof["products"] = prof.cve_id.map(prods).fillna("not yet listed by NIST")
    prof["reference_urls"] = prof.cve_id.map(ref_urls).apply(lambda x: x if isinstance(x, list) else [])
    prof["ibm_xforce_url"] = prof.cve_id.map(xforce).fillna("")
    prof[EXPLOIT_FLAGS] = prof[EXPLOIT_FLAGS].fillna(0).astype(int)
    return prof.fillna({"description": "", "cvss3_severity": "unscored", "attack_vector": "unknown",
                        "privileges_required": "unknown", "user_interaction": "unknown"})


def attack_surface(r) -> str:
    """Short tags for the dashboard, built from data (not the LLM), e.g. 'remote; pre-auth; RCE'."""
    d = str(r.description).lower()
    tags = []
    tags.append({"NETWORK": "remote", "ADJACENT_NETWORK": "adjacent network",
                 "LOCAL": "local", "PHYSICAL": "physical"}.get(r.attack_vector, "vector unknown"))
    if r.privileges_required == "NONE" or re.search(r"unauthenticated|pre-auth|without authentication", d):
        tags.append("pre-auth")
    if r.user_interaction == "NONE":
        tags.append("no user click")
    if re.search(r"remote code execution|arbitrary code|execute (?:arbitrary )?commands|command injection", d):
        tags.append("RCE")
    if any(r[f] == 1 for f in EXPLOIT_FLAGS):
        tags.append("public exploit code")
    return "; ".join(tags)


def facts(r) -> str:
    exploits = [n for n in EXPLOIT_FLAGS if r[n] == 1]
    score = "none" if pd.isna(r.cvss) else f"{r.cvss} {r.cvss3_severity}"
    epss = "no score yet" if pd.isna(r.epss) else f"{r.epss:.3f}"
    return (f"CVE: {r.cve_id} (published {r.published_date})\n"
            f"Description: {str(r.description)[:1500]}\n"
            f"Weakness: {r.weakness}\n"
            f"Affected products: {r.products}\n"
            f"CVSS 3: {score}; attack vector {r.attack_vector}; privileges required "
            f"{r.privileges_required}; user interaction {r.user_interaction}\n"
            f"EPSS (chance of attack in next 30 days): {epss}\n"
            f"Public exploit code: {', '.join(exploits) if exploits else 'none known'}\n"
            f"Priority rank: {r['rank']} of 72,670")


def messages(r):
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": facts(r) + '\n\nReturn JSON with keys "threat_summary", '
             '"weaponization_risk" and "mitigation". Each value is exactly one sentence.'}]


def parse(text):
    m = re.search(r"\{.*\}", text, re.S)
    if not m:
        return None
    try:
        d = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    return {k: str(d[k]).strip() for k in CARD_KEYS} if all(k in d for k in CARD_KEYS) else None


def num(x):
    return None if pd.isna(x) else float(x)


def write_outputs(cards):
    EXPLANATIONS_JSON.write_text(json.dumps(cards, indent=1))

    pd.DataFrame([{"cve_id": c["cve_id"], "attack_surface": c["attack_surface"],
                   "why_fix_first": " ".join(c[k] for k in CARD_KEYS)} for c in cards],
                 columns=THREAT_CARDS_COLUMNS).to_csv(config.THREAT_CARDS_CSV, index=False)

    df = pd.DataFrame(cards)
    df["reference_urls"] = df.reference_urls.apply(lambda u: " | ".join(u))
    df["exploit_code"] = df.exploit_code.apply(lambda x: ", ".join(x) if x else "none")
    df["search_text"] = (df.cve_id + ". " + df.description + " Weakness: " + df.weakness +
                         ". Products: " + df.products + ". " + df.threat_summary + " " +
                         df.weaponization_risk + " Mitigation: " + df.mitigation)
    df.columns = [c.upper() for c in df.columns]
    df.to_csv(CVE_CARDS_CSV, index=False)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--limit", type=int, default=0, help="only the first N CVEs (testing)")
    p.add_argument("--batch-size", type=int, default=16)
    args = p.parse_args()

    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    prof = build_profiles(load_top500())
    if args.limit:
        prof = prof.head(args.limit)

    llm = Granite()
    rows = [r for _, r in prof.iterrows()]
    cards, failed = [], 0
    for i in range(0, len(rows), args.batch_size):
        batch = rows[i:i + args.batch_size]
        for r, text in zip(batch, llm.generate([messages(r) for r in batch])):
            card, tries = parse(text), 0
            while card is None and tries < 4:  # malformed JSON: retry with sampling
                card = parse(llm.generate([messages(r)], sample=True)[0])
                tries += 1
            if card is None:
                failed += 1
                card = {k: "Explanation unavailable." for k in CARD_KEYS}
            cards.append({
                "cve_id": r.cve_id, "rank": int(r["rank"]), "predicted_risk_score": num(r.score),
                "published": r.published_date, "description": r.description,
                "cvss3_score": num(r.cvss), "epss": num(r.epss),
                "exploit_code": [n for n in EXPLOIT_FLAGS if r[n] == 1],
                "weakness": r.weakness, "products": r.products,
                "attack_surface": attack_surface(r),
                "ibm_xforce_url": r.ibm_xforce_url, "reference_urls": r.reference_urls,
                **card,
            })
        print(f"{min(i + args.batch_size, len(rows))}/{len(rows)}")
        write_outputs(cards)  # checkpoint after every batch

    print(f"Wrote {len(cards)} cards ({failed} failed) to {config.THREAT_CARDS_CSV} and {EXPLANATIONS_JSON}")


if __name__ == "__main__":
    main()

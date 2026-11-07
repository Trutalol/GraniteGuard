"""SOC Copilot server: Granite + Snowflake vector search behind a small web API.

Run on a GPU (Colab T4):   python -m ai.serve
It prints a public https://...trycloudflare.com URL and an API key. Put both in the
dashboard machine's .env as COPILOT_URL and COPILOT_KEY; ai.copilot.ask() then calls it.

Endpoints (all but /health need header x-api-key):
  GET  /health
  POST /ask          {"question": "..."} -> {answer, sources, unverified_citations}
  GET  /card/{cve}   one card from Snowflake (404 if not in the top 500)
"""
import argparse
import os
import re
import secrets
import shutil
import subprocess
import threading
from pathlib import Path

import pandas as pd

from ai.common import Granite, load_embedder
from ai.snowflake_api import SnowflakeSQLAPI

CARD_COLS = ("CVE_ID, RANK, DESCRIPTION, THREAT_SUMMARY, WEAPONIZATION_RISK, MITIGATION, "
             "CVSS3_SCORE, EPSS, EXPLOIT_CODE, PRODUCTS, REFERENCE_URLS, IBM_XFORCE_URL")

SYSTEM = ("You are a SOC copilot helping security engineers decide what to patch first. "
          "Answer ONLY from the numbered CVE cards provided. Cite CVE IDs in square brackets, like [CVE-2026-1234]. "
          "Never write URLs or links. "
          "If the cards do not answer the question, say so plainly. "
          "Use short bullet points, one per relevant card, at most 5 bullets. "
          "Go through the cards in the order given and include every card that answers the question.")


def clean_answer(a: str) -> str:
    a = re.sub(r"\]\(https?://[^)]*\)", "]", a)  # [CVE-x](url) -> [CVE-x]
    a = re.sub(r"https?://\S+", "", a)            # invented links (the UI shows the real ones)
    lines = a.rstrip().split("\n")
    if lines and not re.search(r"[.!?)\]]\s*$", lines[-1]):  # drop a cut-off last line
        lines = lines[:-1]
    return "\n".join(lines).strip()


class Copilot:
    def __init__(self):
        self.api = SnowflakeSQLAPI()  # read-only service user
        self.embedder = load_embedder()
        self.llm = Granite()
        self.dim = self.embedder.get_sentence_embedding_dimension()

    def card(self, cve_id):
        df = self.api.query(f"SELECT {CARD_COLS} FROM CVE_CARDS WHERE CVE_ID = ?",
                            {"1": {"type": "TEXT", "value": cve_id.upper()}})
        return None if df.empty else df.iloc[0].to_dict()

    def retrieve(self, question, k=5):
        ql = question.lower()
        ids = sorted(set(re.findall(r"CVE-\d{4}-\d{4,}", question.upper())))
        exact = pd.DataFrame()
        if ids:  # exact CVE lookups, which vector search is bad at
            ph = ",".join("?" * len(ids))
            exact = self.api.query(f"SELECT {CARD_COLS}, 1.0 AS SCORE FROM CVE_CARDS WHERE CVE_ID IN ({ph})",
                                   {str(i + 1): {"type": "TEXT", "value": c} for i, c in enumerate(ids)})

        where = []
        if re.search(r"exploit code|public exploit|\bpoc\b|proof of concept|metasploit|exploit-db|nuclei", ql):
            where.append("EXPLOIT_CODE <> 'none'")
        where_sql = ("WHERE " + " AND ".join(where)) if where else ""
        by_rank = bool(re.search(r"\bfirst\b|\btop\b|most urgent|highest|priorit", ql))

        q = self.embedder.encode([question], normalize_embeddings=True)[0]
        lit = "[" + ",".join(f"{x:.6f}" for x in q) + "]"  # numbers only, safe to inline
        sim = self.api.query(f"""
            SELECT * FROM (
              SELECT {CARD_COLS}, VECTOR_COSINE_SIMILARITY(EMB, {lit}::VECTOR(FLOAT, {self.dim})) AS SCORE
              FROM CVE_CARDS {where_sql}
              ORDER BY SCORE DESC LIMIT 20)
            ORDER BY {"RANK ASC" if by_rank else "SCORE DESC"} LIMIT {k}""")
        ctx = pd.concat([exact, sim]).drop_duplicates("CVE_ID").head(k).reset_index(drop=True)
        # The REST API returns numbers as long strings (9.8000000000000007); round before Granite sees them.
        for col, digits in [("CVSS3_SCORE", 1), ("EPSS", 3)]:
            ctx[col] = pd.to_numeric(ctx[col], errors="coerce").round(digits)
        return ctx, ids

    def ask(self, question, k=5):
        ctx, ids = self.retrieve(question, k)
        missing = [i for i in ids if i not in set(ctx.CVE_ID)]
        cards_txt = "\n\n".join(
            f"Card {n}: [{r.CVE_ID}] priority rank {r.RANK} of 500 | CVSS {r.CVSS3_SCORE} | EPSS {r.EPSS} | "
            f"exploit code: {r.EXPLOIT_CODE} | products: {r.PRODUCTS}\n"
            f"Description: {str(r.DESCRIPTION)[:500]}\n"
            f"Threat: {r.THREAT_SUMMARY}\nWeaponization: {r.WEAPONIZATION_RISK}\nFix: {r.MITIGATION}"
            for n, r in enumerate(ctx.itertuples(), 1))
        note = f"\n\nNote: {', '.join(missing)} is not in our top-500 priority list." if missing else ""
        msgs = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"CVE cards:\n\n{cards_txt}{note}\n\nQuestion: {question}"}]
        answer = clean_answer(self.llm.generate([msgs], max_new_tokens=500)[0])

        sources = [{"cve_id": r.CVE_ID, "rank": int(r.RANK), "score": round(float(r.SCORE), 3),
                    "ibm_xforce_url": r.IBM_XFORCE_URL or "",
                    "reference_urls": str(r.REFERENCE_URLS).split(" | ") if r.REFERENCE_URLS else []}
                   for r in ctx.itertuples()]
        cited = set(re.findall(r"CVE-\d{4}-\d{4,}", answer))
        unverified = sorted(cited - {s["cve_id"] for s in sources})  # should always be empty
        return {"answer": answer, "sources": sources, "unverified_citations": unverified}


def main() -> None:
    import uvicorn
    from fastapi import FastAPI, Header, HTTPException
    from pydantic import BaseModel

    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()

    copilot = Copilot()
    api_key = os.environ.get("COPILOT_KEY") or secrets.token_urlsafe(16)
    app = FastAPI(title="SOC Copilot (IBM Granite + Snowflake)")

    class Question(BaseModel):
        question: str

    def check(key):
        if key != api_key:
            raise HTTPException(401, "bad key")

    @app.get("/health")
    def health():
        return {"ok": True}

    @app.post("/ask")
    def ask(q: Question, x_api_key: str = Header(None)):
        check(x_api_key)
        return copilot.ask(q.question)

    @app.get("/card/{cve_id}")
    def card(cve_id: str, x_api_key: str = Header(None)):
        check(x_api_key)
        c = copilot.card(cve_id)
        if c is None:
            raise HTTPException(404, "not in top 500")
        return c

    threading.Thread(target=lambda: uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning"),
                     daemon=True).start()

    cloudflared = shutil.which("cloudflared") or ("./cloudflared" if Path("cloudflared").exists() else None)
    if not cloudflared:
        print(f"Serving at http://localhost:{args.port} (install cloudflared for a public URL)\nAPI key: {api_key}")
        threading.Event().wait()
    tunnel = subprocess.Popen([cloudflared, "tunnel", "--url", f"http://localhost:{args.port}"],
                              stderr=subprocess.PIPE, text=True)
    for line in tunnel.stderr:
        m = re.search(r"https://[-a-z0-9]+\.trycloudflare\.com", line)
        if m:
            print(f"COPILOT_URL={m.group(0)}\nCOPILOT_KEY={api_key}")
            break
    tunnel.wait()


if __name__ == "__main__":
    main()

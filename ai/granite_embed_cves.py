"""Embed CVE descriptions with IBM Granite (granite-embedding-30m-english), in resumable chunks.

Embeds the CVEs the ranker needs: every snapshot row (2024-2026), the older-CVE training rows,
and every KEV entry. Output: data/processed/granite_emb.npy (float16, L2-normalised) and
granite_emb_ids.csv in the same order.
"""
from pathlib import Path

import numpy as np
import pandas as pd
import torch
from sentence_transformers import SentenceTransformer

from shared import config

MODEL = "ibm-granite/granite-embedding-30m-english"
CHUNK = 20_000


def main() -> None:
    P = config.PROCESSED_DIR
    ids = set(pd.read_parquet(P / "snapshot_features.parquet", columns=["cve_id"]).cve_id)
    aged = P / "aged_features.parquet"
    if aged.exists():
        ids |= set(pd.read_parquet(aged, columns=["cve_id"]).cve_id)
    ids |= set(pd.read_parquet(P / "kev.parquet", columns=["cve_id"]).cve_id)
    corpus = pd.read_parquet(P / "text_corpus.parquet", columns=["cve_id", "description"])
    corpus = corpus[corpus.cve_id.isin(ids)].sort_values("cve_id").reset_index(drop=True)
    print("to embed", len(corpus), flush=True)

    torch.set_num_threads(4)
    model = SentenceTransformer(MODEL, device="cpu", model_kwargs={"torch_dtype": torch.float32})
    model.max_seq_length = 128
    parts_dir = P / "granite_parts"
    parts_dir.mkdir(exist_ok=True)
    texts = corpus.description.fillna("").tolist()
    for start in range(0, len(texts), CHUNK):
        out = parts_dir / f"{start:07d}.npy"
        if out.exists():
            continue
        emb = model.encode(texts[start:start + CHUNK], batch_size=128, normalize_embeddings=True)
        np.save(out, emb.astype(np.float16))
        print("chunk", start, flush=True)
    emb = np.concatenate([np.load(p) for p in sorted(parts_dir.glob("*.npy"))])
    np.save(P / "granite_emb.npy", emb)
    corpus[["cve_id"]].to_csv(P / "granite_emb_ids.csv", index=False)
    print("embedded", emb.shape)


if __name__ == "__main__":
    main()

"""Embed CVE descriptions with IBM Granite and build text features for Person 1.

    python -m ai.granite_embed              # embeddings + features
    python -m ai.granite_embed --features   # features only (embeddings already saved)

Outputs in data/processed/:
  granite_embeddings.npy (+ _index.parquet)  384-dim vectors, kept local (large)
  granite_features.parquet                   cve_id, granite_pc_0..31, 4 keyword flags -> Person 1

Covers CVEs published from 2024 on, every KEV CVE and every scoreboard CVE.
Only `description` and `published` are used, so nothing here leaks 2026 answers.
"""
import argparse

import numpy as np
import pandas as pd

from ai.common import EMBED_MODEL, EMBEDDINGS_INDEX, EMBEDDINGS_NPY, GRANITE_FEATURES, RAW_DIR, load_embedder

TEXT_FLAGS = {
    "flag_rce": r"remote code execution|arbitrary code|execute (?:arbitrary )?commands|command injection|code injection",
    "flag_auth_bypass": r"authentication bypass|bypass(?:es|ing)? (?:the )?authentication|unauthenticated|pre-auth|without authentication",
    "flag_edge_device": r"\bvpn\b|firewall|gateway|fortios|fortigate|forti|pan-os|ivanti|citrix|netscaler|sonicwall|big-ip|\bcisco asa\b|juniper",
    "flag_memory_corruption": r"buffer overflow|use[- ]after[- ]free|heap[- ]based|stack[- ]based|out[- ]of[- ]bounds write|memory corruption",
}


def embed(batch_size=128):
    v = pd.read_csv(RAW_DIR / "vulnerabilities.csv", usecols=["cve_id", "published", "description"])
    kev = pd.read_csv(RAW_DIR / "known_exploited.csv", usecols=["cve_id"])
    sb = pd.read_csv(RAW_DIR / "scoreboard_2026.csv", usecols=["cve_id"])

    keep = (v.published >= "2024-01-01") | v.cve_id.isin(kev.cve_id) | v.cve_id.isin(sb.cve_id)
    v = v[keep].drop_duplicates("cve_id").reset_index(drop=True)
    v["description"] = v.description.fillna("")
    print(f"Embedding {len(v):,} descriptions with {EMBED_MODEL}")

    emb = load_embedder().encode(v.description.tolist(), batch_size=batch_size, normalize_embeddings=True,
                                 show_progress_bar=True, convert_to_numpy=True).astype(np.float32)
    EMBEDDINGS_NPY.parent.mkdir(parents=True, exist_ok=True)
    np.save(EMBEDDINGS_NPY, emb)
    v[["cve_id", "published"]].to_parquet(EMBEDDINGS_INDEX)
    print(f"Saved {emb.shape} to {EMBEDDINGS_NPY}")


def features():
    from sklearn.decomposition import PCA

    emb = np.load(EMBEDDINGS_NPY)
    idx = pd.read_parquet(EMBEDDINGS_INDEX)
    # Fit PCA on pre-2026 CVEs only, so the 2026 benchmark never shapes the features.
    pca = PCA(n_components=32, random_state=0).fit(emb[(idx.published < "2026-01-01").values])
    reduced = pca.transform(emb)

    desc = (pd.read_csv(RAW_DIR / "vulnerabilities.csv", usecols=["cve_id", "description"])
              .drop_duplicates("cve_id").set_index("cve_id").description
              .reindex(idx.cve_id).fillna("").str.lower())

    feat = pd.DataFrame(reduced, columns=[f"granite_pc_{i}" for i in range(32)])
    feat.insert(0, "cve_id", idx.cve_id.values)
    for col, pattern in TEXT_FLAGS.items():
        feat[col] = desc.str.contains(pattern, regex=True).astype(int).values
    feat.to_parquet(GRANITE_FEATURES)
    print(f"Saved {feat.shape} to {GRANITE_FEATURES}")
    print("flag rates:\n", feat[list(TEXT_FLAGS)].mean().round(3))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--features", action="store_true", help="only rebuild granite_features.parquet")
    p.add_argument("--batch-size", type=int, default=128)
    args = p.parse_args()
    if not args.features:
        embed(args.batch_size)
    features()


if __name__ == "__main__":
    main()

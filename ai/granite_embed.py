"""Embed CVE descriptions with IBM Granite."""
import numpy as np
import pandas as pd

from shared import config

EMBEDDINGS_NPY = config.PROCESSED_DIR / "granite_embeddings.npy"


def main() -> None:
    from sentence_transformers import SentenceTransformer

    top = pd.read_csv(config.TOP500_CSV)
    model = SentenceTransformer(config.env("GRANITE_EMBED_MODEL"))
    vectors = model.encode(top["description"].fillna("").tolist(), show_progress_bar=True)
    np.save(EMBEDDINGS_NPY, vectors)
    print(f"Saved {vectors.shape} to {EMBEDDINGS_NPY}")


if __name__ == "__main__":
    main()

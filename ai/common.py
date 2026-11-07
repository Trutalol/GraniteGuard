"""Shared helpers for the ai/ package: paths, Granite models, Snowflake key-pair auth."""
from __future__ import annotations

import threading
from pathlib import Path

from shared import config

# Raw CSVs from data.zip. In Colab, set DATA_DIR=/content/data in .env or the environment.
RAW_DIR = Path(config.env("DATA_DIR") or config.RAW_DIR)
PROCESSED_DIR = config.PROCESSED_DIR

# Person 2 outputs (threat_cards.csv itself comes from shared/config.py)
EMBEDDINGS_NPY = PROCESSED_DIR / "granite_embeddings.npy"
EMBEDDINGS_INDEX = PROCESSED_DIR / "granite_embeddings_index.parquet"
GRANITE_FEATURES = PROCESSED_DIR / "granite_features.parquet"   # -> Person 1
EXPLANATIONS_JSON = PROCESSED_DIR / "granite_explanations.json"  # full cards -> Person 3
CVE_CARDS_CSV = PROCESSED_DIR / "cve_cards.csv"                  # upload file for Snowflake

EMBED_MODEL = config.env("GRANITE_EMBED_MODEL") or "ibm-granite/granite-embedding-30m-english"
INSTRUCT_MODEL = config.env("GRANITE_INSTRUCT_MODEL") or "ibm-granite/granite-3.3-2b-instruct"

SF_ACCOUNT = config.env("SNOWFLAKE_ACCOUNT") or ""
SF_WAREHOUSE = config.env("SNOWFLAKE_WAREHOUSE") or "DATATHON_WH"
SF_DATABASE = config.env("SNOWFLAKE_DATABASE") or "DATATHON"
SF_SCHEMA = config.env("SNOWFLAKE_SCHEMA") or "COPILOT"
SF_LOADER_KEY = config.env("SNOWFLAKE_LOADER_KEY") or "keys/loader_key.p8"
SF_APP_KEY = config.env("SNOWFLAKE_APP_KEY") or "keys/copilot_app_key.p8"

EXPLOIT_FLAGS = ["exploitdb", "metasploit", "nuclei", "poc_github"]


def device() -> str:
    import torch
    return "cuda" if torch.cuda.is_available() else "cpu"


def load_embedder():
    """Granite embedding model. 512-token cap and fp16 avoid the T4 out-of-memory error."""
    from sentence_transformers import SentenceTransformer
    dev = device()
    model = SentenceTransformer(EMBED_MODEL, device=dev)
    model.max_seq_length = 512
    if dev == "cuda":
        model.half()
    return model


class Granite:
    """IBM Granite Instruct with batched, deterministic generation."""

    def __init__(self):
        import torch
        from transformers import AutoModelForCausalLM, AutoTokenizer
        self.torch = torch
        self.dev = device()
        self.tok = AutoTokenizer.from_pretrained(INSTRUCT_MODEL)
        self.tok.padding_side = "left"
        if self.tok.pad_token is None:
            self.tok.pad_token = self.tok.eos_token
        dtype = torch.float16 if self.dev == "cuda" else torch.float32
        self.model = AutoModelForCausalLM.from_pretrained(INSTRUCT_MODEL, torch_dtype=dtype).to(self.dev).eval()
        self.lock = threading.Lock()  # one generation at a time when serving

    def generate(self, message_lists, max_new_tokens=220, sample=False):
        texts = [self.tok.apply_chat_template(m, tokenize=False, add_generation_prompt=True)
                 for m in message_lists]
        enc = self.tok(texts, return_tensors="pt", padding=True).to(self.dev)
        kwargs = {"max_new_tokens": max_new_tokens, "pad_token_id": self.tok.pad_token_id,
                  "do_sample": sample}
        if sample:
            kwargs["temperature"] = 0.7
        with self.lock, self.torch.no_grad():
            out = self.model.generate(**enc, **kwargs)
        return self.tok.batch_decode(out[:, enc.input_ids.shape[1]:], skip_special_tokens=True)


def private_key(path):
    from cryptography.hazmat.primitives import serialization
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def connect(user="DATATHON_LOADER", key_path=None, role="COPILOT_WRITER"):
    """Python-connector session for a key-pair service user (writer by default)."""
    import snowflake.connector
    from cryptography.hazmat.primitives import serialization
    der = private_key(key_path or SF_LOADER_KEY).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return snowflake.connector.connect(account=SF_ACCOUNT, user=user, private_key=der, role=role,
                                       warehouse=SF_WAREHOUSE, database=SF_DATABASE, schema=SF_SCHEMA)

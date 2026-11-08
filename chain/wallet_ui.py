"""Streamlit bridge to the engineer's Solflare/Phantom wallet.

chain/web/index.html is a tiny Streamlit component. It runs in a same-origin frame, so it can use
the wallet provider the browser extension injected into the dashboard page. Rendering it opens the
wallet popup; once the engineer approves, it returns the signed transaction to Python.
"""
import streamlit.components.v1 as components

from chain.solana_attest import WEB_DIR

_wallet = components.declare_component("graniteguard_wallet", path=str(WEB_DIR))


def wallet_sign(request: dict, key: str):
    """Ask the wallet to sign `request` (from start_wallet_signoff). Returns {"request_id", "wtx"} or None."""
    return _wallet(request_id=request["request_id"], memo=request["memo"], payer=request["payer"],
                   rpc=request["rpc"], key=key, default=None)

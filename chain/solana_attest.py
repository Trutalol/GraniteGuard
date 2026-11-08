"""Proof of Patch: tamper-proof CVE fix sign-offs anchored on Solana devnet.

When an engineer signs off a fix, we hash the full sign-off record (SHA-256) and write only that
fingerprint to Solana. Nothing sensitive goes on-chain: no CVE ID, product, host or company,
because "company X has not patched CVE-Y" is itself an attack hint on a public ledger.

    GG1|attest|<sha256 of the sign-off record>|status=patched

Anyone holding the record can later recompute the hash and check it against the chain: same hash
means the record is exactly what was signed, at that block time, by that wallet. Change one
character and verification fails.

Zero new dependencies: the transaction is assembled byte by byte, signed with Ed25519 from the
`cryptography` package and sent with `requests` to Solana's JSON-RPC API. The hash rides in an
instruction of Solana's Memo program, which records it in the transaction and the program logs.

    python -m chain.solana_attest setup     # create the devnet wallet and request free test SOL
    python -m chain.solana_attest balance

Engineers sign with their own Solflare or Phantom wallet (start_wallet_signoff / complete_wallet_signoff):
their wallet is the Memo signer and the GraniteGuard wallet only pays the fee.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from shared import config

RPC_URL = config.env("SOLANA_RPC_URL") or "https://api.devnet.solana.com"
CLUSTER = config.env("SOLANA_CLUSTER") or "devnet"
KEYPAIR_PATH = config.ROOT / (config.env("SOLANA_KEYPAIR") or "keys/solana_devnet.json")
SIGNOFF_LOG = config.PROCESSED_DIR / "signoffs.jsonl"   # full records, kept off-chain
ORG_ID = config.env("GG_ORG_ID") or "graniteguard-demo"

MEMO_PROGRAM_ID = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
PREFIX = "GG1|attest|"
STATUSES = {
    "patched": "Patched / upgraded",
    "mitigated": "Mitigated (workaround or config change)",
    "not_affected": "Not affected (software not in our environment)",
    "risk_accepted": "Risk accepted (documented exception)",
}

# ------------------------------------------------------------------ base58 (Solana addresses)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        n = n * 58 + _B58.index(ch)
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


# ------------------------------------------------------------------ wallet
class Keypair:
    """Ed25519 keypair stored in the Solana CLI format (JSON array of 64 bytes)."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key
        self.public_bytes = private_key.public_key().public_bytes_raw()
        self.address = b58encode(self.public_bytes)

    @classmethod
    def generate(cls) -> "Keypair":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: Path = KEYPAIR_PATH) -> "Keypair":
        raw = bytes(json.loads(Path(path).read_text()))
        return cls(Ed25519PrivateKey.from_private_bytes(raw[:32]))

    def save(self, path: Path = KEYPAIR_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(list(self._key.private_bytes_raw() + self.public_bytes)))

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def load_or_create_keypair(path: Path = KEYPAIR_PATH) -> Keypair:
    if Path(path).exists():
        return Keypair.load(path)
    kp = Keypair.generate()
    kp.save(path)
    return kp


# ------------------------------------------------------------------ transaction bytes
def _shortvec(n: int) -> bytes:
    """Solana's compact-u16 length prefix."""
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def build_memo_message(payer: bytes, recent_blockhash: str, memo: bytes) -> bytes:
    """Legacy transaction message: fee payer signs, Memo program is the only instruction."""
    header = bytes([1, 0, 1])  # 1 signature, 0 read-only signed, 1 read-only unsigned (the program)
    keys = _shortvec(2) + payer + b58decode(MEMO_PROGRAM_ID)
    instruction = bytes([1]) + _shortvec(0) + _shortvec(len(memo)) + memo  # program index 1, no accounts
    return header + keys + b58decode(recent_blockhash) + _shortvec(1) + instruction


def build_memo_transaction(kp: Keypair, recent_blockhash: str, memo: str) -> bytes:
    message = build_memo_message(kp.public_bytes, recent_blockhash, memo.encode())
    return _shortvec(1) + kp.sign(message) + message


# ------------------------------------------------------------------ JSON-RPC
def rpc(method: str, params=None, timeout: int = 30):
    r = requests.post(RPC_URL, timeout=timeout,
                      json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
    r.raise_for_status()
    j = r.json()
    if "error" in j:
        raise RuntimeError(f"Solana {method}: {j['error'].get('message', j['error'])}")
    return j["result"]


def balance_sol(address: str) -> float:
    return rpc("getBalance", [address, {"commitment": "confirmed"}])["value"] / 1e9


def airdrop(address: str, sol: float = 1.0) -> str:
    return rpc("requestAirdrop", [address, int(sol * 1e9), {"commitment": "confirmed"}])


def wait_for(signature: str, timeout: float = 45) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = rpc("getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])["value"][0]
        if status and status.get("err"):
            raise RuntimeError(f"Transaction failed: {status['err']}")
        if status and status.get("confirmationStatus") in ("confirmed", "finalized"):
            return status
        time.sleep(1.5)
    raise TimeoutError("Transaction not confirmed yet; check the Explorer link in a minute.")


def explorer_url(signature: str) -> str:
    return f"https://explorer.solana.com/tx/{signature}?cluster={CLUSTER}"


# ------------------------------------------------------------------ attestation
def canonical(record: dict) -> str:
    """Stable JSON for hashing: sorted keys, no whitespace, so the same record always hashes the same."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(record: dict) -> str:
    return hashlib.sha256(canonical(record).encode()).hexdigest()


def make_record(cve_id: str, status: str, action: str, reference: str, engineer: str, rank=None) -> dict:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {list(STATUSES)}")
    return {
        "v": 1,
        "org": ORG_ID,
        "cve_id": cve_id.upper(),
        "rank": None if rank is None else int(rank),
        "status": status,
        "action": action.strip(),
        "reference": reference.strip(),
        "engineer": engineer.strip(),
        "signed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "nonce": base64.urlsafe_b64encode(os.urandom(9)).decode(),  # stops guessing the hash from public facts
    }


def sign_off(record: dict, kp: Keypair | None = None) -> dict:
    """Anchor the record's fingerprint on Solana and append the full record to the off-chain log."""
    kp = kp or load_or_create_keypair()
    digest = fingerprint(record)
    memo = f"{PREFIX}{digest}|status={record['status']}"
    blockhash = rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"]
    tx = build_memo_transaction(kp, blockhash, memo)
    signature = rpc("sendTransaction", [base64.b64encode(tx).decode(),
                                        {"encoding": "base64", "preflightCommitment": "confirmed"}])
    wait_for(signature)

    entry = {"cve_id": record["cve_id"], "record": record, "sha256": digest, "signature": signature,
             "signer": kp.address, "fee_payer": kp.address, "method": "service",
             "cluster": CLUSTER, "explorer": explorer_url(signature)}
    SIGNOFF_LOG.parent.mkdir(parents=True, exist_ok=True)
    with SIGNOFF_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def load_signoffs() -> list[dict]:
    if not SIGNOFF_LOG.exists():
        return []
    return [json.loads(line) for line in SIGNOFF_LOG.read_text(encoding="utf-8").splitlines() if line.strip()]


def latest_signoffs() -> dict:
    """cve_id -> most recent sign-off entry."""
    return {e["cve_id"]: e for e in load_signoffs()}


def onchain_memo(signature: str) -> dict:
    """Fetch the transaction and pull out our memo, its signers and the block time."""
    tx = rpc("getTransaction", [signature, {"encoding": "json", "commitment": "confirmed",
                                            "maxSupportedTransactionVersion": 0}])
    if tx is None:
        raise RuntimeError("Transaction not found on this cluster.")
    msg = tx["transaction"]["message"]
    keys = msg["accountKeys"]
    memo, memo_signers = None, []
    for ins in msg["instructions"]:
        if keys[ins["programIdIndex"]] == MEMO_PROGRAM_ID:
            memo = b58decode(ins["data"]).decode("utf-8", "replace")
            memo_signers = [keys[i] for i in ins.get("accounts", [])]
    signer = memo_signers[0] if memo_signers else keys[0]  # the attesting wallet (fee payer if none listed)
    return {"memo": memo, "signer": signer, "fee_payer": keys[0],
            "block_time": tx.get("blockTime"), "slot": tx.get("slot")}


# ------------------------------------------------------------------ engineer's own wallet (Solflare / Phantom)
# The engineer's wallet signs the attestation as the Memo signer (the Memo program rejects the
# transaction unless that wallet really signed). The GraniteGuard wallet only pays the fee, so
# engineers need no SOL. In the dashboard, chain/wallet_ui.py asks the wallet extension to sign.
WEB_DIR = Path(__file__).with_name("web")
PENDING_FILE = config.PROCESSED_DIR / "pending_signoffs.json"


def _pending() -> dict:
    return json.loads(PENDING_FILE.read_text()) if PENDING_FILE.exists() else {}


def _save_pending(pending: dict) -> None:
    PENDING_FILE.parent.mkdir(parents=True, exist_ok=True)
    PENDING_FILE.write_text(json.dumps(pending))


def start_wallet_signoff(record: dict, kp: Keypair | None = None) -> dict:
    """Remember the record as pending; return what the wallet needs to sign it."""
    kp = kp or load_or_create_keypair()
    digest = fingerprint(record)
    pending = _pending()
    pending[digest] = record
    _save_pending(pending)
    return {"request_id": digest, "cve": record["cve_id"], "memo": f"{PREFIX}{digest}|status={record['status']}",
            "payer": kp.address, "rpc": RPC_URL}


def reset_session_log() -> Path | None:
    """Start a fresh sign-off list: archive the old log (never deleted) and drop pending requests."""
    archived = None
    if SIGNOFF_LOG.exists() and SIGNOFF_LOG.stat().st_size:
        archived = SIGNOFF_LOG.with_name(f"signoffs-{datetime.now().strftime('%Y%m%d-%H%M%S')}.jsonl")
        SIGNOFF_LOG.rename(archived)
    PENDING_FILE.unlink(missing_ok=True)
    return archived


def _read_shortvec(buf: bytes, i: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        b = buf[i]
        i += 1
        n |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return n, i


def parse_transaction(raw: bytes) -> dict:
    """Split a legacy transaction into signatures and the parts of its message we check."""
    n_sigs, i = _read_shortvec(raw, 0)
    sigs = [raw[i + 64 * k: i + 64 * (k + 1)] for k in range(n_sigs)]
    msg_start = i + 64 * n_sigs
    m = raw[msg_start:]
    if m[0] & 0x80:
        raise ValueError("Versioned transactions are not supported here.")
    n_required, j = m[0], 3
    n_keys, j = _read_shortvec(m, j)
    keys = [m[j + 32 * k: j + 32 * (k + 1)] for k in range(n_keys)]
    j += 32 * n_keys + 32  # account keys + recent blockhash
    n_ix, j = _read_shortvec(m, j)
    instructions = []
    for _ in range(n_ix):
        program = m[j]
        n_acc, j = _read_shortvec(m, j + 1)
        accounts = list(m[j: j + n_acc])
        j += n_acc
        n_data, j = _read_shortvec(m, j)
        instructions.append({"program": program, "accounts": accounts, "data": m[j: j + n_data]})
        j += n_data
    return {"sigs": sigs, "msg_start": msg_start, "message": m, "n_required": n_required,
            "keys": keys, "instructions": instructions}


COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"
LIGHTHOUSE_PROGRAM_ID = "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"  # Phantom's read-only safety assertions
MAX_PRIORITY_MICROLAMPORTS = 1_000_000  # cap on the priority fee a wallet may add (we pay the fee)


def _check_instructions(tx: dict, keys: list, memo_program: bytes) -> dict:
    """Return the single Memo instruction, allowing only harmless instructions wallets add.

    Solflare and Phantom often add compute-budget instructions (priority fee settings), and Phantom
    may add Lighthouse assertions that only read state. Anything else is rejected, and no
    instruction may use the GraniteGuard fee wallet as an account.
    """
    compute_budget, lighthouse = b58decode(COMPUTE_BUDGET_PROGRAM_ID), b58decode(LIGHTHOUSE_PROGRAM_ID)
    memos = []
    for ins in tx["instructions"]:
        program = keys[ins["program"]]
        if 0 in ins["accounts"]:
            raise ValueError("An instruction tries to use the GraniteGuard fee wallet.")
        if program == memo_program:
            memos.append(ins)
        elif program == compute_budget:
            data = ins["data"]
            if not data or data[0] not in (1, 2, 3, 4):
                raise ValueError("Unexpected compute-budget instruction.")
            if data[0] == 3 and int.from_bytes(data[1:9], "little") > MAX_PRIORITY_MICROLAMPORTS:
                raise ValueError("The wallet set a priority fee above GraniteGuard's limit.")
        elif program != lighthouse:
            raise ValueError(f"Unexpected instruction from program {b58encode(program)}.")
    if len(memos) != 1:
        raise ValueError("The transaction must contain exactly one attestation.")
    return memos[0]


def complete_wallet_signoff(wtx_b64: str, kp: Keypair | None = None) -> dict:
    """Check the Phantom-signed transaction, add the fee-payer signature, submit and log it."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    kp = kp or load_or_create_keypair()
    wtx_b64 = wtx_b64.replace("-", "+").replace("_", "/")  # accept base64 or base64url
    raw = bytearray(base64.b64decode(wtx_b64 + "=" * (-len(wtx_b64) % 4)))
    tx = parse_transaction(bytes(raw))
    keys, memo_program = tx["keys"], b58decode(MEMO_PROGRAM_ID)

    if keys[0] != kp.public_bytes:
        raise ValueError("The fee payer is not this GraniteGuard wallet.")
    ix = _check_instructions(tx, keys, memo_program)
    memo = ix["data"].decode("utf-8", "replace")
    if not memo.startswith(PREFIX):
        raise ValueError("Not a GraniteGuard attestation.")
    digest = memo.split("|")[2]
    pending = _pending()
    if digest not in pending:
        raise ValueError("No pending sign-off matches this signature (it may already be submitted).")
    if len(ix["accounts"]) != 1 or not 0 < ix["accounts"][0] < tx["n_required"]:
        raise ValueError("The attestation must be signed by exactly one engineer wallet.")

    w = ix["accounts"][0]
    try:  # the engineer's wallet really signed this exact message
        Ed25519PublicKey.from_public_bytes(keys[w]).verify(tx["sigs"][w], tx["message"])
    except InvalidSignature:
        raise ValueError("The wallet signature is invalid.") from None

    raw[1:65] = kp.sign(tx["message"])  # fee-payer signature goes in slot 0
    signature = rpc("sendTransaction", [base64.b64encode(bytes(raw)).decode(),
                                        {"encoding": "base64", "preflightCommitment": "confirmed"}])
    wait_for(signature)

    record = pending.pop(digest)
    _save_pending(pending)
    engineer_wallet = b58encode(keys[w])
    entry = {"cve_id": record["cve_id"], "record": record, "sha256": digest, "signature": signature,
             "signer": engineer_wallet, "fee_payer": kp.address, "method": "wallet",
             "cluster": CLUSTER, "explorer": explorer_url(signature)}
    SIGNOFF_LOG.parent.mkdir(parents=True, exist_ok=True)
    with SIGNOFF_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def verify(entry: dict, record: dict | None = None) -> dict:
    """Recompute the hash of `record` (default: the stored one) and compare it with the chain."""
    record = record if record is not None else entry["record"]
    local = fingerprint(record)
    chain = onchain_memo(entry["signature"])
    onchain_hash = chain["memo"].split("|")[2] if chain["memo"] and chain["memo"].startswith(PREFIX) else None
    when = (datetime.fromtimestamp(chain["block_time"], timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            if chain["block_time"] else "unknown")
    return {"match": local == onchain_hash, "local_hash": local, "onchain_hash": onchain_hash,
            "signer": chain["signer"], "signer_ok": chain["signer"] == entry["signer"],
            "block_time": when, "slot": chain["slot"]}


# ------------------------------------------------------------------ CLI
def main() -> None:
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "setup"
    kp = load_or_create_keypair()
    print(f"Wallet: {kp.address}  ({CLUSTER}, key file {KEYPAIR_PATH})")
    if cmd == "setup":
        try:
            sig = airdrop(kp.address, 1.0)
            wait_for(sig)
            print("Airdropped 1 devnet SOL.")
        except Exception as exc:
            print(f"Airdrop failed ({exc}).\nGet free devnet SOL at https://faucet.solana.com for the wallet above.")
    print(f"Balance: {balance_sol(kp.address):.4f} SOL (each sign-off costs about 0.000005)")


if __name__ == "__main__":
    main()

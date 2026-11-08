# chain/: Proof of Patch on Solana

GraniteGuard ranks what to fix first and explains why. This folder closes the loop: when an engineer
signs off a fix, the sign-off becomes a **tamper-proof, timestamped record anchored on Solana**.
Auditors, managers or customers can later check that a CVE was signed off by that wallet at that
time, and that nobody has edited the record since. A normal database can't promise that, because
an admin can quietly change a row.

## What goes on-chain (and what doesn't)

A public ledger that says "company X has not patched CVE-Y" would hand attackers a target list.
So the full record stays off-chain and only its SHA-256 fingerprint is written to Solana:

```
GG1|attest|935f45db5d5515246fe594def383f82263f5e7572b0e814f47ea67cfa6e11308|status=patched
```

The off-chain record holds the organisation, CVE, rank, resolution, what was done, the change
ticket or fixed version, the engineer, a UTC timestamp and a random nonce. The nonce stops anyone
guessing the hash from public facts. The record is serialised as canonical JSON (sorted keys, no
whitespace), so the same record always produces the same hash.

## How it works

- **Sign off:** hash the record, build a Solana transaction carrying the attestation in an
  instruction to Solana's Memo program, have the engineer's wallet sign it (see below), add the
  fee-payer signature, send it to devnet and wait for confirmation. The full record and the transaction signature go into
  `data/processed/signoffs.jsonl`.
- **Verify:** fetch the transaction from Solana, read the attestation, recompute the hash from the
  record and compare. A match proves the record is unchanged and shows the signer wallet and block
  time. Changing a single character makes verification fail.
- **No Solana SDK on the server:** the backend parses and checks the wallet-signed transaction byte
  by byte (compact-u16 lengths, account keys, instruction data), verifies Ed25519 signatures and adds
  its own with `cryptography`, and talks to Solana's JSON-RPC API with `requests`. Both packages were
  already in the project. We checked the results against the official `solders` library.

## Signing with your own wallet (Solflare or Phantom)

Engineers sign with their own Solflare or Phantom wallet, right inside the dashboard:

1. In the **Sign off** tab, fill in the fix and press **Sign off on Solana**. GraniteGuard saves the
   record as pending and opens a dialog.
2. The dialog holds a tiny Streamlit component (`chain/web/index.html`, bridged by
   `chain/wallet_ui.py`). Its frame is same-origin with the dashboard, so it can use the wallet the
   browser extension injected into the page, and the wallet's approval popup opens directly; no new tab.
3. The component builds a transaction where the **engineer's wallet is the Memo signer** and the
   **GraniteGuard wallet is the fee payer**, so engineers need no SOL, and returns it once signed.
4. GraniteGuard checks it before submitting: the fee payer is its own wallet, there is exactly one
   Memo instruction carrying a pending fingerprint, and the engineer's Ed25519 signature is valid.
   It then adds the fee-payer signature, sends it and shows the proof.

The Memo program rejects any transaction where a listed signer didn't really sign, so the chain
itself proves which wallet attested to the fix. Tampered records, forged wallet signatures and
replays of an already-submitted transaction are all rejected. The component uses the official
`@solana/web3.js` 1.98.0 bundle, shipped with the repo, so it loads no outside scripts.

## In the dashboard

Each CVE's page has a **Sign off** tab: choose a resolution (patched, mitigated, not affected, risk
accepted), say what was done, add the ticket or fixed version, and sign with your wallet. The record
then shows the fingerprint, the transaction, the signing wallet and a Solana Explorer link, and the
list shows a "Fix signed on Solana" badge. **Verify on Solana** opens a dialog that checks the record
against the chain; editing the recorded action first shows tampering being caught.

Each time Streamlit starts, the previous sign-off list is moved to `signoffs-<timestamp>.jsonl` (never
deleted), so every run starts clean. The transactions themselves stay on Solana permanently.

## Setup

```bash
py -m chain.solana_attest      # creates the fee wallet keys/solana_devnet.json and asks devnet for free SOL
```

Engineers switch their wallet to devnet (Solflare: Settings → Network → Devnet; Phantom:
Settings → Developer Settings → Testnet Mode → Solana Devnet). They need no SOL themselves.

If the devnet airdrop is rate-limited, paste the printed wallet address into
https://faucet.solana.com. Each sign-off costs about 0.000005 devnet SOL. `keys/` is gitignored.

## Limits and next steps

- Runs on **devnet**, and the signing page is served locally next to the dashboard. The GraniteGuard
  wallet (`keys/solana_devnet.json`) only pays fees and needs a little devnet SOL.
- The off-chain log is a local file. Next: store it in Snowflake beside the threat cards.
- A custom Solana program could keep one account per sign-off, so all fixes for an organisation
  can be listed straight from the chain.

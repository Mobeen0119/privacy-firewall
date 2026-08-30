# midnight-side

Blockchain (Midnight) + cryptography module for the AI Privacy Firewall
project. Scope: notarize audit-log hash chains on-chain via a Compact
contract. Does not include the firewall/policy/PII modules (separate repo
component, owned separately).

## What's here

- `audit/` — Python: builds a tamper-evident SHA-256 hash chain over an
  audit log, signs the resulting root hash (Ed25519), and verifies both.
- `contract/commit.compact` — Midnight Compact contract: stores the latest
  committed root hash on-chain (`commit` circuit) and can be read back
  (`get_latest` circuit).
- `scripts/` — TypeScript: wallet setup, contract compile/deploy, and
  committing a root hash on-chain.
- `docs/fallback_demo.md` — offline demo path if a live testnet isn't
  reachable.

## Setup

```
npm install
```

Install the Compact compiler (one-time, needs a real terminal/WSL, not
covered by `npm install`):
```
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/midnightntwrk/compact/releases/latest/download/compact-installer.sh | sh
source $HOME/.local/bin/env
compact update
```

Run a local proof server (Docker required):
```
docker run -d -p 6300:6300 midnightntwrk/proof-server:latest midnight-proof-server -v
```

## Wallet

```
npm run generate-wallet
```
writes a fresh seed to `seed.txt`. Fund the derived address via the Preview
faucet (https://midnight-tmnight-preview.nethermind.dev/), then **delegate**
the tNIGHT to generate spendable tDUST (needed to pay any transaction fee) —
via a wallet like Lace: fund the Midnight account, then use its
"Generate DUST" action on that account.

Environment variables:

- `MIDNIGHT_WALLET_PASSWORD` — **required**, no default; encrypts the local
  private-state store (>= 8 chars).
- `MIDNIGHT_WALLET_SEED` or `MIDNIGHT_WALLET_SEED_FILE` (defaults to `seed.txt`);
  must be exactly 64 hex chars.
- `MIDNIGHT_NETWORK` — one of `preview` (default), `testnet`, `undeployed`.
  Single switch: drives both the runtime network id and the wallet-facade
  network id.
- `MIDNIGHT_INDEXER_URL` / `MIDNIGHT_INDEXER_WS_URL` / `MIDNIGHT_PROOF_SERVER_URL`
  (Preview defaults built in).
- `MIDNIGHT_CONTRACT_SIGNING_KEY` — optional managed contract-authority key
  (64 hex); otherwise derived from the seed.
- `MIDNIGHT_AUDIT_OWNER_SECRET` / `_FILE`, or `MIDNIGHT_AUDIT_OWNER_PK` — owner
  authority for the `commit` circuit (see `contract/README.md`).
- `MIDNIGHT_CONTRACT_ADDRESS` — optional override; `npm run commit` otherwise
  reads `deployment.json`.
- `MIDNIGHT_SYNC_TIMEOUT_MS` (default 180000), `MIDNIGHT_ALLOW_UNSYNCED=1` to
  proceed without a fully synced wallet.
- `MIDNIGHT_FEE_BLOCKS_MARGIN` (default 10) — bump and re-run if a tx expires
  under congestion. `MIDNIGHT_TX_CONFIRM_TIMEOUT_MS` / `_INTERVAL_MS` tune the
  post-submit indexer inclusion poll.
- `MIDNIGHT_CONTRACT_ADDRESS_RE` — override the contract-address format check.
- `AUDIT_CHAIN_SALT` — >= 16 random bytes (hex) mixed into every hash-chain
  step; makes the published root un-recomputable without the salt (set it the
  same way wherever the chain is verified).

## Run

```
npm run compile              # compiles contract + writes build/commit/.source-sha256
npm run generate-owner-secret
npm run deploy               # one-time: deploys, writes deployment.json (0600)
npm run commit               # commits audit/root_hash.txt on-chain
npm run pipeline             # audit -> sign -> commit -> verify over EXISTING audit_log.jsonl
npm run demo                 # generates a fake log, then runs the pipeline
npm test                     # off-chain TS harness (node --test)
npm run test:py              # pytest audit/
```

## Known open issue (as of last session)

`npm run deploy` / `npm run commit` can fail with either:

- a "keys.signing" schema error — fixed by supplying an explicit
  `signingKey` (see `scripts/deploy_contract.ts` /
  `scripts/commit_to_chain.ts`, already applied in this package), or
- `ContractConfigurationError: Failed to configure constructor context
  with coin public key` (`decodeZswapLocalState` crash) — this is an
  **upstream bug in `@midnight-ntwrk/compact-js`**, reproduced across
  several mutually-consistent version combinations of the Midnight SDK.
  Not caused by this code. If you hit this, the fix is either a
  `compact-js` update from Midnight, or downgrading the whole stack to
  the exact older combination used in Midnight's official "hello world"
  example (`compact-runtime@0.16.0`, `ledger-v8@8.0.3`,
  `midnight-js-contracts@4.0.2`) with a matching older Compact compiler
  (`compact update <older-version>` — check `compact update` with no
  argument for what's available, and match against Midnight's release
  compatibility matrix at https://docs.midnight.network/relnotes/support-matrix).

Everything else — contract logic, hash chain, signing, wallet key
derivation, DUST delegation flow — is confirmed working end to end.

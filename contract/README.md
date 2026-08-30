# commit.compact

Owner-gated Midnight notary contract. Stores the latest committed audit
root hash on-chain, a running commit counter, and an append-only
accumulator that cryptographically links every accepted commit.

## Ledger state

- `owner: Bytes<32>` — immutable owner identity, set at deploy time.
  Equal to `persistentHash(["midnight-side:audit-owner:v1", ownerSecret])`.
  The secret is never stored on-chain.
- `latestHash: Bytes<32>` — append-only accumulator:
  `latestHash_{n+1} = SHA256(latestHash_n || epoch_n || newHash_n)`,
  genesis `0x00..00`. Any reorder / insertion / dropped commit changes it.
- `lastRoot: Bytes<32>` — most recent raw committed root hash (what
  `get_latest` returns).
- `commitCount: Counter` — strictly monotonic commit sequence number.

## Circuits

- `constructor(ownerPk: Bytes<32>)` — sets `owner` once. `ownerPk` is the
  value of `ownerPublicKey` for the owner secret; pass it directly via
  `MIDNIGHT_AUDIT_OWNER_PK` or let `deploy_contract.ts` derive it.
- `commit(newHash: Bytes<32>, ownerSk: Bytes<32>, expectedEpoch: Uint<64>)`
  — **fails closed**: aborts with no state change unless
  `ownerPublicKey(ownerSk) == owner`, `expectedEpoch == commitCount`,
  `newHash` is non-zero, and `newHash != lastRoot` (no all-zero or
  replayed root). On success folds `newHash` into `latestHash`, sets
  `lastRoot`, and increments `commitCount`. `ownerSk` and `expectedEpoch`
  are private circuit inputs, proven in zero knowledge, never disclosed.
  `commit_to_chain.ts` reads the current on-chain `commitCount` for
  `expectedEpoch` (override with `MIDNIGHT_COMMIT_EPOCH`).
- `get_latest(): Bytes<32>` — returns the current `lastRoot`.
- `ownerPublicKey(ownerSk: Bytes<32>): Bytes<32>` — pure helper;
  domain-separated hash of the owner secret. Callable off-chain as
  `pureCircuits.ownerPublicKey(secret)`.

## Owner secret

```
npm run generate-owner-secret     # -> audit/firewall_owner_secret.key (0600)
```

The deployer needs this file or `MIDNIGHT_AUDIT_OWNER_PK`; the committer
(`npm run commit`) needs the file (or `MIDNIGHT_AUDIT_OWNER_SECRET`).

## Compile

```
npm run compile
```

Produces `build/commit/` — required before deploy/commit scripts can run.

## Deploy

```
npm run deploy
```

Prints a contract address and deploy tx hash, and writes `deployment.json`
at the repo root (mode 0600) with the address, network, owner identity,
and a public id of the contract-maintenance signing authority.
`npm run commit` reads that file — no manual copy of the address needed.

The signing authority is deterministic: it is either
`MIDNIGHT_CONTRACT_SIGNING_KEY` (managed key) or HKDF-derived from the
wallet seed. It is never randomly sampled, so redeploy / commit from the
same seed always uses the same authority.

- Network: Preview
- Contract address: (see `deployment.json` after first deploy)
- Deploy tx hash: (see `deployment.json` after first deploy)

## No-network fallback

See `../docs/fallback_demo.md` if a live deploy isn't reachable at demo time.

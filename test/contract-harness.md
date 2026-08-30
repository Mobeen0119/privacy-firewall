# Contract test harness (audit finding M-16)

Circuit-level tests need the Compact compiler and a Midnight local
environment (proof server + a funded seed on `undeployed`/local), so they
are not part of `npm test`. Run them against a local node.

## Setup

```
npm run compile
docker run -d -p 6300:6300 midnightntwrk/proof-server:latest midnight-proof-server -v
export MIDNIGHT_NETWORK=undeployed
export MIDNIGHT_WALLET_SEED=<local funded seed>
export MIDNIGHT_WALLET_PASSWORD=<something>
npm run generate-owner-secret
```

## Cases

| # | Action | Expected |
|---|--------|----------|
| 1 | Deploy with `ownerPk = pureCircuits.ownerPublicKey(secret)` | `owner` ledger cell == `ownerPk`; `deployment.json` written |
| 2 | `commit(root, correctSecret, epoch=0)` | tx succeeds; `lastRoot==root`; `accumulator` advances from `0^32`; `commitCount==1` |
| 3 | `commit(root, WRONG secret, epoch=1)` | tx rejected: `unauthorized - caller does not hold the owner key` |
| 4 | `commit(root, correctSecret, epoch=0)` again (stale) | tx rejected: `epoch mismatch - stale or out-of-order commit` |
| 5 | `commit(root2, correctSecret, epoch=1)` | succeeds; `accumulator` changes again; `commitCount==2` |
| 6 | `commit(root3, correctSecret, epoch=5)` (gap) | rejected: epoch mismatch |
| 6a | `commit(0x00…00, correctSecret, epoch=2)` | rejected: `newHash must not be all-zero` (L-2) |
| 6b | `commit(root2, correctSecret, epoch=2)` (same as last) | rejected: `newHash duplicates the current lastRoot` (L-2) |
| 7 | `get_latest()` after case 5 | returns `root2` |
| 8 | Re-run `npm run deploy` without `npm run compile` after editing `commit.compact` | fails: `build output is stale ... run 'npm run compile'` (M-14) |

## Driver sketch

Use `scripts/onchain.ts::readOnchainState(address)` to read `lastRoot` /
`accumulator` / `commitCount` between steps, and
`scripts/commit_to_chain.ts::commitToChain({ epoch })` to submit. Assert
the accumulator by snapshotting it before/after each commit and checking
it changed and stays consistent across a replay of the same sequence
(the exact preimage encoding is `persistentHash` of the compiled
`Vector<3, Bytes<32>>` - reproduce it via the contract, not by hand).

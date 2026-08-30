# Fallback demo (no live testnet)

If deploy/commit fails at demo time, show the audit + crypto layer works
standalone, without a live chain. Uses placeholder context values for the
signature (`preview` / `DEMO` / epoch `0`); on a real deployment these are
the network, contract address, and current `commitCount`.

1. `python audit/fake_audit_generator.py` — creates `audit_log.jsonl`.
2. `python audit/hash_chain.py` — prints the root hash, writes
   `audit_chain.jsonl` and `root_hash.txt`. Fails loudly if the log is
   empty (no more silent `0…0` root).
3. `python audit/sign.py generate` — creates a signing keypair (set
   `FIREWALL_KEY_PASSPHRASE` first to encrypt it; `--force` to rotate).
4. Sign the root, bound to context:
   ```
   ROOT=$(cat audit/root_hash.txt)
   python audit/sign.py sign "$ROOT" preview DEMO 0
   ```
5. Show `contract/commit.compact` + the compiled `build/commit/` output as
   evidence the on-chain side is real code.
6. Verify (no `--onchain-root`, so the on-chain check is SKIPPED):
   ```
   python audit/verify.py audit_log.jsonl "$ROOT" <signature_hex> \
     --network preview --contract DEMO --epoch 0
   ```
   → PASS.
7. Edit one record in `audit_log.jsonl` (even whitespace / key order),
   rerun step 6 → FAIL — tamper detected.

For the full live flow (`npm run demo` / `npm run pipeline`) the pipeline
reads an existing `audit_log.jsonl` and fails if it is absent; only
`npm run demo` fabricates sample data.

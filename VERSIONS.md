# Dependency version matrix (audit findings H-5 / H-6)

## Why this file exists

`package.json` previously shipped the exact `@midnight-ntwrk/*` combination
the README documents as broken (`ContractConfigurationError` /
`decodeZswapLocalState` crash in `@midnight-ntwrk/compact-js`), with **no
lockfile**, so `npm install` re-resolved the whole transitive tree on
every run.

## What changed

- Pinned to the known-good support matrix from the README's "hello world"
  reference:

  | package | was | now |
  |---|---|---|
  | `@midnight-ntwrk/compact-runtime` | 0.19.0 | **0.16.0** |
  | `@midnight-ntwrk/ledger-v8` | 8.1.1 | **8.0.3** |
  | `@midnight-ntwrk/midnight-js-contracts` | 4.1.1 | **4.0.2** |
  | `@midnight-ntwrk/midnight-js-*` (all others) | 4.1.1 | **4.0.2** (lockstep) |

- `overrides` now covers **every** `@midnight-ntwrk/*` package (was: only
  `ledger-v8` + `compact-runtime`), so transitive copies pulled in by the
  wallet SDK are forced to the same versions - no duplicate ledger /
  runtime instances.

- `devDependencies` pinned exactly (dropped `^`). Added `packageManager`
  and `engines.node`.

## Open items - MUST be done in a real environment (cannot run npm here)

1. **Generate and commit the lockfile:**

   ```
   rm -rf node_modules
   npm install --package-lock-only    # writes package-lock.json, no install
   npm ci                             # verify it resolves + installs clean
   git add package-lock.json
   ```

   Use `npm ci` (not `npm install`) in CI from now on.

2. **Confirm `@midnight-ntwrk/compact-js` (kept at 2.5.1) against the
   support matrix** at
   <https://docs.midnight.network/relnotes/support-matrix> for the
   `compact-runtime@0.16.0` / `ledger-v8@8.0.3` /
   `midnight-js-contracts@4.0.2` row. The README says only "compact-js
   matched" without a number. If the matched version predates the
   `CompiledContract.make(...).pipe(...)` fluent API, `deploy_contract.ts`
   / `commit_to_chain.ts` need the older `deployContract({ contract, ... })`
   call shape - the contract itself is unaffected.

3. **Confirm the `@midnight-ntwrk/wallet-sdk-*` versions** for the same
   matrix row (left at current versions here; they appear to version
   independently of `midnight-js-*`).

4. Match the **Compact compiler** to the runtime:
   `compact update <version>` (see `compact update` with no argument for
   what is installable), per the same support matrix.

5. `tsconfig.json` no longer sets `skipLibCheck` (audit finding L-9). If
   `tsc --noEmit` then reports errors *inside*
   `node_modules/@midnight-ntwrk/**/*.d.ts` (an SDK packaging issue, not
   this repo's code), re-add `"skipLibCheck": true` and open an upstream
   issue rather than editing the SDK types.

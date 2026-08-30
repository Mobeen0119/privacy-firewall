/**
 * commit_to_chain.ts
 *
 * Takes the latest root hash produced by audit/hash_chain.py
 * (written to audit/root_hash.txt) and commits it on-chain by
 * calling the `commit` circuit on the already-deployed contract.
 *
 * Run deploy_contract.ts once first, then run this every time you
 * want to publish a new root hash (e.g. after each demo run, or on
 * a timer/webhook from the AI side's audit logger).
 */

import { readFile } from "fs/promises";
import { submitCallTx } from "@midnight-ntwrk/midnight-js-contracts";
import { CompiledContract } from "@midnight-ntwrk/compact-js";
import { createProviders } from "./providers.js";
import { Contract } from "../build/commit/contract/index.js";

const CONTRACT_ADDRESS = process.env.MIDNIGHT_CONTRACT_ADDRESS ?? "TODO-paste-address-from-deploy_contract.ts";

async function loadRootHash(): Promise<string> {
  const content = await readFile(new URL("../audit/root_hash.txt", import.meta.url), "utf-8");
  return content.trim();
}

async function main() {
  const rootHash = await loadRootHash();
  const providers = await createProviders();

  const compiledContract = CompiledContract.make("CommitContract", Contract).pipe(
    CompiledContract.withVacantWitnesses,
    CompiledContract.withCompiledFileAssets("../build/commit")
  );

  console.log(`Committing root hash on-chain: ${rootHash}`);

  const result = await submitCallTx(providers, {
    compiledContract,
    contractAddress: CONTRACT_ADDRESS,
    circuitId: "commit",
    // commit.compact expects Bytes<32> - convert the hex string root
    // hash into raw bytes before passing it as an argument.
    args: [Buffer.from(rootHash, "hex")],
  });

  console.log("Committed.");
  console.log("Tx hash:", result.public.txHash);
}

main().catch((err) => {
  console.error("Commit failed:", err);
  process.exit(1);
});

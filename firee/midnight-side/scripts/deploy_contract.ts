/**
 * deploy_contract.ts
 *
 * Deploys commit.compact to the Midnight testnet, ONE TIME.
 * After it succeeds, save the printed contract address into
 * contract/README.md - commit_to_chain.ts needs it for every call after.
 *
 * Prereqs:
 *   1. commit.compact compiled (compactc contract/commit.compact -o build/commit)
 *   2. Wallet funded with tDUST from the testnet faucet
 *   3. Proof server running locally (docker-compose up proof-server, or
 *      whatever the current Midnight docs say - check before running)
 */

import { CompiledContract } from "@midnight-ntwrk/compact-js";
import { deployContract } from "@midnight-ntwrk/midnight-js-contracts";
import { createProviders } from "./providers.js";

// TODO: 'Contract' here is the generated class from compiling commit.compact.
// After running compactc, import it from the generated output directory,
// e.g.: import { Contract } from '../build/commit/contract/index.cjs';
// Left as a placeholder import path until the contract is actually compiled.
import { Contract } from "../build/commit/contract/index.js";

async function main() {
  const providers = await createProviders();

  const compiledContract = CompiledContract.make("CommitContract", Contract).pipe(
    CompiledContract.withVacantWitnesses,
    CompiledContract.withCompiledFileAssets("../build/commit")
  );

  console.log("Deploying commit.compact to testnet...");

  const deployed = await deployContract(providers, { compiledContract });

  console.log("Deployed.");
  console.log("Contract address:", deployed.deployTxData.public.contractAddress);
  console.log("Deploy tx hash:", deployed.deployTxData.public.txHash);
  console.log("\nSave this contract address into contract/README.md and into");
  console.log("MIDNIGHT_CONTRACT_ADDRESS for commit_to_chain.ts to use.");
}

main().catch((err) => {
  console.error("Deploy failed:", err);
  process.exit(1);
});

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { CompiledContract } from "@midnight-ntwrk/compact-js";
import { deployContract } from "@midnight-ntwrk/midnight-js-contracts";
import { createProviders } from "./providers.js";
import { Contract } from "../build/commit/contract/index.js";

setNetworkId("preview");

console.log("SCRIPT STARTED");

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
}

main().catch((err) => {
  console.error("Deploy failed:", err);
  process.exit(1);
});
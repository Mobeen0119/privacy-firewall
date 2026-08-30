/**
 * deploy_contract.ts
 *
 * One-time deploy of commit.compact. The contract-maintenance signing
 * key is deterministic / externally managed (never `sampleSigningKey()`
 * - audit finding C-2); the build is checked against the source hash
 * before deploy (M-14); the result is persisted atomically to
 * deployment.json (mode 0600) with address, tx hash, network id, and
 * timestamp (M-18); provider handles are disposed and the process exits
 * cleanly (M-13).
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CompiledContract } from "@midnight-ntwrk/compact-js";
import { deployContract } from "@midnight-ntwrk/midnight-js-contracts";
import { createProviders } from "./providers.js";
import { Contract, pureCircuits } from "../build/commit/contract/index.js";
import {
  DEPLOYMENT_PATH,
  NETWORK,
  NETWORK_ID,
  assertBuildFresh,
  loadContractSigningKey,
  signingAuthorityKeyId,
  sha256File,
  writeDeploymentRecord,
} from "./deployment.js";
import { CONTRACT_SRC, ZK_CONFIG_DIR, applyRuntimeNetworkId } from "./env.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const OWNER_SECRET_FILE =
  process.env.MIDNIGHT_AUDIT_OWNER_SECRET_FILE ??
  path.resolve(HERE, "../audit/firewall_owner_secret.key");

function loadOwnerSecret(): Uint8Array {
  const envHex = process.env.MIDNIGHT_AUDIT_OWNER_SECRET?.trim();
  const raw = envHex ? envHex : readFileSync(OWNER_SECRET_FILE, "utf-8").trim();
  if (!/^[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error(
      "owner secret must be 64 hex chars (32 bytes); set MIDNIGHT_AUDIT_OWNER_SECRET, " +
        "point MIDNIGHT_AUDIT_OWNER_SECRET_FILE at a key file, or set MIDNIGHT_AUDIT_OWNER_PK",
    );
  }
  return Uint8Array.from(Buffer.from(raw, "hex"));
}

function loadOwnerPublicKey(): Uint8Array {
  const pkHex = process.env.MIDNIGHT_AUDIT_OWNER_PK?.trim();
  if (pkHex) {
    if (!/^[0-9a-fA-F]{64}$/.test(pkHex)) {
      throw new Error("MIDNIGHT_AUDIT_OWNER_PK must be 64 hex chars (32 bytes)");
    }
    return Uint8Array.from(Buffer.from(pkHex, "hex"));
  }
  return pureCircuits.ownerPublicKey(loadOwnerSecret());
}

async function main(): Promise<void> {
  applyRuntimeNetworkId();
  assertBuildFresh(CONTRACT_SRC, ZK_CONFIG_DIR); // M-14: build matches source

  const signingKey = loadContractSigningKey(); // deterministic / managed - never sampled
  const ownerPk = loadOwnerPublicKey();

  const { providers, dispose } = await createProviders();
  try {
    const compiledContract = CompiledContract.make("CommitContract", Contract).pipe(
      CompiledContract.withVacantWitnesses,
      CompiledContract.withCompiledFileAssets(ZK_CONFIG_DIR),
    );

    console.log(`Deploying commit.compact to ${NETWORK} (${NETWORK_ID}) ...`);

    const deployed = await deployContract(providers, {
      compiledContract,
      signingKey,
      args: [ownerPk], // constructor(ownerPk: Bytes<32>)
    });

    const contractAddress = deployed.deployTxData.public.contractAddress;
    const deployTxHash = deployed.deployTxData.public.txHash;

    writeDeploymentRecord({
      network: NETWORK,
      networkId: NETWORK_ID,
      contractAddress,
      deployTxHash,
      ownerPublicKey: Buffer.from(ownerPk).toString("hex"),
      signingAuthorityKeyId: signingAuthorityKeyId(signingKey),
      compiledContractSha256: sha256File(CONTRACT_SRC),
      deployedAt: new Date().toISOString(),
    });

    console.log("Deployed.");
    console.log("Contract address:", contractAddress);
    console.log("Deploy tx hash:  ", deployTxHash);
    console.log(`Wrote ${DEPLOYMENT_PATH} (mode 0600).`);
  } finally {
    await dispose();
  }
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error("Deploy failed:", err);
    process.exit(1);
  });

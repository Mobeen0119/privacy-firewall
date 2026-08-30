/**
 * commit_to_chain.ts
 *
 * Commits the latest audit-log root hash (audit/root_hash.txt) on-chain
 * by calling the `commit` circuit on the deployed contract.
 *
 * Exposed as `commitToChain()` so run_pipeline.ts can call it in-process
 * (audit finding H-8); still runnable directly via `npm run commit`.
 * Provider handles are disposed and the process exits cleanly (M-13).
 */

import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { submitCallTx } from "@midnight-ntwrk/midnight-js-contracts";
import { CompiledContract } from "@midnight-ntwrk/compact-js";
import { createProviders } from "./providers.js";
import { Contract } from "../build/commit/contract/index.js";
import {
  NETWORK,
  assertBuildFresh,
  loadContractSigningKey,
  readDeploymentRecord,
  signingAuthorityKeyId,
} from "./deployment.js";
import { CONTRACT_SRC, ZK_CONFIG_DIR, applyRuntimeNetworkId } from "./env.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT_HASH_FILE = path.resolve(HERE, "../audit/root_hash.txt");
const OWNER_SECRET_FILE =
  process.env.MIDNIGHT_AUDIT_OWNER_SECRET_FILE ??
  path.resolve(HERE, "../audit/firewall_owner_secret.key");

const HEX64 = /^[0-9a-fA-F]{64}$/;

// L-7: strict contract-address shape. Midnight addresses are hex (optional
// 0x); the length band is deliberately wide. Override via
// MIDNIGHT_CONTRACT_ADDRESS_RE if a future address format needs it.
const DEFAULT_ADDR_RE = /^(?:0x)?[0-9a-fA-F]{32,130}$/;

function assertContractAddress(addr: string, source: string): void {
  const pattern = process.env.MIDNIGHT_CONTRACT_ADDRESS_RE
    ? new RegExp(process.env.MIDNIGHT_CONTRACT_ADDRESS_RE)
    : DEFAULT_ADDR_RE;
  if (!addr || /^TODO/i.test(addr) || !pattern.test(addr)) {
    throw new Error(
      `contract address from ${source} is not valid: ${JSON.stringify(addr)} ` +
        `(must match ${pattern}); run 'npm run deploy' or set MIDNIGHT_CONTRACT_ADDRESS`,
    );
  }
}

/** Validate audit/root_hash.txt strictly before any proving happens (H-7). */
async function loadRootHash(): Promise<Buffer> {
  let raw: string;
  try {
    raw = (await readFile(ROOT_HASH_FILE, "utf-8")).trim();
  } catch {
    throw new Error(`${ROOT_HASH_FILE} not found; run 'python hash_chain.py' first`);
  }
  if (raw.length === 0) throw new Error("root_hash.txt is empty");
  if (!HEX64.test(raw)) {
    throw new Error(
      `root_hash.txt must match /^[0-9a-fA-F]{64}$/ (32-byte hash); got ${JSON.stringify(raw)}`,
    );
  }
  const buf = Buffer.from(raw, "hex");
  if (buf.length !== 32) throw new Error("root hash did not decode to exactly 32 bytes");
  return buf;
}

function loadOwnerSecret(): Uint8Array {
  const envHex = process.env.MIDNIGHT_AUDIT_OWNER_SECRET?.trim();
  const raw = envHex ? envHex : readFileSync(OWNER_SECRET_FILE, "utf-8").trim();
  if (!HEX64.test(raw)) {
    throw new Error(
      "owner secret must be 64 hex chars (32 bytes); set MIDNIGHT_AUDIT_OWNER_SECRET " +
        "or point MIDNIGHT_AUDIT_OWNER_SECRET_FILE at a key file",
    );
  }
  return Uint8Array.from(Buffer.from(raw, "hex"));
}

interface PublicDataProvider {
  queryContractState(address: string): Promise<{ data: unknown } | null>;
}

/** Current on-chain commitCount = the epoch this commit must target. */
async function resolveEpoch(
  publicDataProvider: PublicDataProvider,
  contractAddress: string,
): Promise<bigint> {
  const override = process.env.MIDNIGHT_COMMIT_EPOCH?.trim();
  if (override) {
    if (!/^\d+$/.test(override)) {
      throw new Error("MIDNIGHT_COMMIT_EPOCH must be a non-negative integer");
    }
    return BigInt(override);
  }

  let state: { data: unknown } | null;
  try {
    state = await publicDataProvider.queryContractState(contractAddress);
  } catch (err) {
    throw new Error(
      `could not query on-chain contract state for the commit epoch ` +
        `(${(err as Error).message}); set MIDNIGHT_COMMIT_EPOCH to the current commitCount`,
    );
  }
  if (!state) return 0n; // contract not observed on-chain yet -> first commit

  try {
    const mod = (await import("../build/commit/contract/index.js")) as {
      ledger: (data: unknown) => { commitCount: bigint | number };
    };
    return BigInt(mod.ledger(state.data).commitCount);
  } catch (err) {
    throw new Error(
      `could not decode contract ledger state (${(err as Error).message}); ` +
        `set MIDNIGHT_COMMIT_EPOCH to the current commitCount`,
    );
  }
}

export interface CommitOptions {
  /** Epoch to target; resolved from chain if omitted. */
  epoch?: bigint;
}

export async function commitToChain(opts: CommitOptions = {}): Promise<string> {
  assertBuildFresh(CONTRACT_SRC, ZK_CONFIG_DIR); // M-14

  const deployment = readDeploymentRecord();

  const contractAddress =
    process.env.MIDNIGHT_CONTRACT_ADDRESS?.trim() || deployment.contractAddress;
  assertContractAddress(
    contractAddress,
    process.env.MIDNIGHT_CONTRACT_ADDRESS?.trim()
      ? "MIDNIGHT_CONTRACT_ADDRESS"
      : "deployment.json",
  );
  if (deployment.network !== NETWORK) {
    throw new Error(
      `network mismatch: deployment.json says '${deployment.network}', scripts configured for '${NETWORK}'`,
    );
  }

  const signingKey = loadContractSigningKey();
  if (signingAuthorityKeyId(signingKey) !== deployment.signingAuthorityKeyId) {
    throw new Error(
      "contract signing authority mismatch: the loaded key is not the one recorded at deploy time. " +
        "Set MIDNIGHT_CONTRACT_SIGNING_KEY / MIDNIGHT_WALLET_SEED to the deploy-time values.",
    );
  }

  applyRuntimeNetworkId();

  const rootHash = await loadRootHash(); // validated before proving (H-7)
  const ownerSecret = loadOwnerSecret();

  const { providers, dispose } = await createProviders();
  try {
    const epoch =
      opts.epoch ??
      (await resolveEpoch(
        providers.publicDataProvider as unknown as PublicDataProvider,
        contractAddress,
      ));

    const compiledContract = CompiledContract.make("CommitContract", Contract).pipe(
      CompiledContract.withVacantWitnesses,
      CompiledContract.withCompiledFileAssets(ZK_CONFIG_DIR),
    );

    console.log(`Committing root hash on-chain: ${rootHash.toString("hex")}`);
    console.log(`Target epoch (current commitCount): ${epoch.toString()}`);

    const result = await submitCallTx(providers, {
      compiledContract,
      contractAddress,
      circuitId: "commit",
      // commit(newHash: Bytes<32>, ownerSk: Bytes<32>, expectedEpoch: Uint<64>)
      args: [rootHash, ownerSecret, epoch],
      signingKey,
    });

    const txHash = String(result.public.txHash);
    console.log("Committed. Tx hash:", txHash);
    return txHash;
  } finally {
    ownerSecret.fill(0);
    await dispose();
  }
}

// Run only when invoked directly (npm run commit), not when imported.
if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  commitToChain()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error("Commit failed:", err);
      process.exit(1);
    });
}

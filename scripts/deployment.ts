/**
 * deployment.ts
 *
 * Shared, non-random contract-authority handling for the deploy and
 * commit scripts. Replaces every operational use of
 * `sampleSigningKey()` (audit finding C-2):
 *
 *  - the contract-maintenance signing key is either an externally
 *    managed key (env) or is deterministically derived from the wallet
 *    seed, so it is stable and reproducible across deploy and every
 *    later commit;
 *  - `deployment.json` is written atomically at mode 0600 and records
 *    the contract address, the network, and a public identifier of the
 *    signing authority, so `commit_to_chain.ts` can prove it loaded the
 *    same authority the deploy used - without the secret ever touching
 *    disk.
 */

import { chmodSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { createHash, hkdfSync } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { MIDNIGHT_NETWORK, FACADE_NETWORK_ID_NAME, loadSeedHex } from "./env.js";

export { BUILD_STAMP, sha256File, assertBuildFresh } from "./build_meta.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Network the scripts target. Driven by MIDNIGHT_NETWORK (see env.ts). */
export const NETWORK = MIDNIGHT_NETWORK;

/** Wallet-facade network id name that pairs with NETWORK (audit M-10). */
export const NETWORK_ID = FACADE_NETWORK_ID_NAME;

export const DEPLOYMENT_PATH = path.join(REPO_ROOT, "deployment.json");

/** Order of the secp256k1 group - a valid scalar is in [1, n-1]. */
const SECP256K1_N =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Deterministic secp256k1 contract-maintenance signing key, as the raw
 * hex string the SDK schema expects.
 *
 * Priority:
 *   1. MIDNIGHT_CONTRACT_SIGNING_KEY - an externally managed / HSM-exported
 *      key (64 hex chars). Use this in production.
 *   2. HKDF-SHA256 over the wallet seed with a fixed domain label, so the
 *      same seed always yields the same contract authority. Never random,
 *      never unpersisted (this is the `sampleSigningKey()` replacement).
 */
export function loadContractSigningKey(): string {
  const managed = process.env.MIDNIGHT_CONTRACT_SIGNING_KEY?.trim();
  if (managed) {
    if (!/^[0-9a-fA-F]{64}$/.test(managed)) {
      throw new Error(
        "MIDNIGHT_CONTRACT_SIGNING_KEY must be exactly 64 hex chars (32 bytes)",
      );
    }
    return managed.toLowerCase();
  }

  const ikm = Buffer.from(loadSeedHex(), "hex");
  if (ikm.length === 0) {
    throw new Error("wallet seed is empty; cannot derive contract signing key");
  }

  // Rejection-sample so the scalar is in range. The probability of a
  // single miss is ~2^-128; the loop bound is a safety net only.
  for (let counter = 0; counter < 256; counter++) {
    const info = Buffer.from(
      `midnight-side/contract-maintenance-authority/v1/${counter}`,
    );
    const okm = Buffer.from(
      hkdfSync("sha256", ikm, Buffer.alloc(0), info, 32),
    );
    const scalar = BigInt("0x" + okm.toString("hex"));
    if (scalar > 0n && scalar < SECP256K1_N) return okm.toString("hex");
  }
  throw new Error("failed to derive an in-range secp256k1 signing key");
}

/**
 * Public identifier for a contract signing key: a domain-separated
 * SHA-256 commitment to the key bytes. Recorded in deployment.json and
 * recomputed by the commit script to detect a wrong / rotated authority
 * key. Reveals nothing about the secret.
 */
export function signingAuthorityKeyId(signingKeyHex: string): string {
  return createHash("sha256")
    .update("midnight-side/contract-authority-id/v1")
    .update(Buffer.from(signingKeyHex, "hex"))
    .digest("hex");
}

export interface DeploymentRecord {
  network: string;
  networkId: string;
  contractAddress: string;
  deployTxHash: string;
  /** hex, Bytes<32> - the on-chain `owner` identity. */
  ownerPublicKey: string;
  /** SHA-256 id of the contract-maintenance signing key. */
  signingAuthorityKeyId: string;
  /** SHA-256 of contract/commit.compact at deploy time. */
  compiledContractSha256: string;
  deployedAt: string;
}

const REQUIRED_FIELDS = [
  "network",
  "contractAddress",
  "ownerPublicKey",
  "signingAuthorityKeyId",
] as const;

/** Atomic, 0600 write of deployment.json (defeats umask, no torn file). */
export function writeDeploymentRecord(rec: DeploymentRecord): void {
  const tmp = `${DEPLOYMENT_PATH}.tmp-${process.pid}`;
  const body = JSON.stringify(rec, null, 2) + "\n";
  writeFileSync(tmp, body, { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, DEPLOYMENT_PATH);
  chmodSync(DEPLOYMENT_PATH, 0o600);
}

export function readDeploymentRecord(): DeploymentRecord {
  let raw: string;
  try {
    raw = readFileSync(DEPLOYMENT_PATH, "utf-8");
  } catch {
    throw new Error(
      `deployment.json not found at ${DEPLOYMENT_PATH}; run 'npm run deploy' first`,
    );
  }
  let rec: Partial<DeploymentRecord>;
  try {
    rec = JSON.parse(raw) as Partial<DeploymentRecord>;
  } catch {
    throw new Error(`deployment.json is not valid JSON`);
  }
  for (const k of REQUIRED_FIELDS) {
    if (typeof rec[k] !== "string" || (rec[k] as string).length === 0) {
      throw new Error(`deployment.json is missing required field '${k}'`);
    }
  }
  return rec as DeploymentRecord;
}

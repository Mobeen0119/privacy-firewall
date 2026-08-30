/**
 * env.ts
 *
 * Single source of truth for network selection, endpoint URLs, and the
 * wallet seed / private-state password (audit findings M-6, M-9, M-10,
 * M-11). Both `providers.ts` and `deployment.ts` read from here so the
 * global runtime network id and the wallet-facade network id can never
 * drift apart.
 */

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { NetworkId } from "@midnight-ntwrk/wallet-sdk-abstractions";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** One variable drives everything: MIDNIGHT_NETWORK (default "preview"). */
export const MIDNIGHT_NETWORK = (process.env.MIDNIGHT_NETWORK ?? "preview").toLowerCase();

interface NetEntry {
  runtime: string; // string id passed to setNetworkId()
  facade: NetworkId.NetworkId; // enum used in the wallet facade config
  facadeName: string; // human/JSON-friendly name of `facade`
}

const NET_TABLE: Record<string, NetEntry> = {
  preview: { runtime: "preview", facade: NetworkId.NetworkId.TestNet, facadeName: "TestNet" },
  testnet: { runtime: "testnet", facade: NetworkId.NetworkId.TestNet, facadeName: "TestNet" },
  undeployed: {
    runtime: "undeployed",
    facade: NetworkId.NetworkId.Undeployed,
    facadeName: "Undeployed",
  },
};

const NET = NET_TABLE[MIDNIGHT_NETWORK];
if (!NET) {
  throw new Error(
    `unknown MIDNIGHT_NETWORK='${MIDNIGHT_NETWORK}'; expected one of: ${Object.keys(NET_TABLE).join(", ")}`,
  );
}

export const RUNTIME_NETWORK_ID = NET.runtime;
export const FACADE_NETWORK_ID = NET.facade;
export const FACADE_NETWORK_ID_NAME = NET.facadeName;

let applied = false;
/** Apply the global runtime network id exactly once. */
export function applyRuntimeNetworkId(): void {
  if (applied) return;
  setNetworkId(RUNTIME_NETWORK_ID);
  applied = true;
}

export const INDEXER_HTTP_URL =
  process.env.MIDNIGHT_INDEXER_URL ??
  "https://indexer.preview.midnight.network/api/v4/graphql";
export const INDEXER_WS_URL =
  process.env.MIDNIGHT_INDEXER_WS_URL ??
  "wss://indexer.preview.midnight.network/api/v4/graphql/ws";
export const PROOF_SERVER_URL =
  process.env.MIDNIGHT_PROOF_SERVER_URL ?? "http://127.0.0.1:6300";
export const ZK_CONFIG_DIR = path.join(REPO_ROOT, "build", "commit");
export const CONTRACT_SRC = path.join(REPO_ROOT, "contract", "commit.compact");

const SEED_RE = /^[0-9a-fA-F]{64}$/;

function readSeedRaw(): string {
  const inline = process.env.MIDNIGHT_WALLET_SEED?.trim();
  if (inline) return inline;
  const file =
    process.env.MIDNIGHT_WALLET_SEED_FILE ?? path.join(REPO_ROOT, "seed.txt");
  return readFileSync(file, "utf-8").trim();
}

/** Wallet seed as bytes; strict 64-hex validation (M-11). */
export function loadSeed(): Uint8Array {
  const raw = readSeedRaw();
  if (!SEED_RE.test(raw)) {
    throw new Error(
      "wallet seed must match /^[0-9a-fA-F]{64}$/ (32 bytes); " +
        "set MIDNIGHT_WALLET_SEED or MIDNIGHT_WALLET_SEED_FILE",
    );
  }
  return Uint8Array.from(Buffer.from(raw, "hex"));
}

/** Wallet seed as lowercase hex; same strict validation. */
export function loadSeedHex(): string {
  const raw = readSeedRaw();
  if (!SEED_RE.test(raw)) {
    throw new Error("wallet seed must match /^[0-9a-fA-F]{64}$/ (32 bytes)");
  }
  return raw.toLowerCase();
}

/** Private-state store password - required, no default (M-9). */
export function requireWalletPassword(): string {
  const pw = process.env.MIDNIGHT_WALLET_PASSWORD;
  if (!pw || pw.length < 8) {
    throw new Error(
      "MIDNIGHT_WALLET_PASSWORD is required (>= 8 chars); it encrypts the local " +
        "private-state store and has no built-in default",
    );
  }
  return pw;
}

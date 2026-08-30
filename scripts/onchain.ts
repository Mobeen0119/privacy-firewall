/**
 * onchain.ts
 *
 * Lightweight read of the deployed contract's ledger state straight from
 * the Midnight indexer (no wallet facade needed). Used by the pipeline to
 * verify end-to-end that the root hash actually landed on-chain
 * (audit finding M-4).
 */

import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import {
  INDEXER_HTTP_URL,
  INDEXER_WS_URL,
  applyRuntimeNetworkId,
} from "./env.js";

export interface OnchainState {
  /** hex, Bytes<32> - most recent raw committed root (contract `lastRoot`). */
  lastRoot: string;
  /** hex, Bytes<32> - append-only accumulator (contract `latestHash`). */
  accumulator: string;
  /** contract `commitCount`. */
  commitCount: bigint;
}

function toHex(v: unknown): string {
  if (typeof v === "string") return v.replace(/^0x/, "").toLowerCase();
  if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
  if (Array.isArray(v)) return Buffer.from(v as number[]).toString("hex");
  throw new Error(`cannot render on-chain value as hex: ${Object.prototype.toString.call(v)}`);
}

export async function readOnchainState(
  contractAddress: string,
): Promise<OnchainState | null> {
  applyRuntimeNetworkId();
  const pdp = indexerPublicDataProvider(INDEXER_HTTP_URL, INDEXER_WS_URL);
  try {
    const state = await pdp.queryContractState(contractAddress);
    if (!state) return null;

    const mod = (await import("../build/commit/contract/index.js")) as {
      ledger: (data: unknown) => {
        latestHash: unknown;
        lastRoot: unknown;
        commitCount: bigint | number;
      };
    };
    const l = mod.ledger((state as { data: unknown }).data);
    return {
      lastRoot: toHex(l.lastRoot),
      accumulator: toHex(l.latestHash),
      commitCount: BigInt(l.commitCount),
    };
  } finally {
    try {
      await (pdp as { close?: () => unknown }).close?.();
    } catch {
      /* ignore */
    }
  }
}

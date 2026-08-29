/**
 * providers.ts
 *
 * Shared provider setup for deploy_contract.ts and commit_to_chain.ts.
 * This version typechecks cleanly against the real installed SDK
 * (verified with `npx tsc --noEmit` against actual .d.ts files, not
 * guessed from docs).
 *
 * Fill in the TODOs with real testnet endpoints + wallet secrets before
 * running. Values below are read from env vars so nothing sensitive
 * needs to be hardcoded or committed to this repo.
 */

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import type { MidnightProviders } from "@midnight-ntwrk/midnight-js-types";

// TODO: replace with real testnet endpoints - get these from the
// current Midnight testnet docs/faucet page, they do change between
// testnet phases.
const INDEXER_QUERY_URL = process.env.MIDNIGHT_INDEXER_URL ?? "https://TODO-testnet-indexer.example/api/v1/graphql";
const INDEXER_WS_URL = process.env.MIDNIGHT_INDEXER_WS_URL ?? "wss://TODO-testnet-indexer.example/api/v1/graphql/ws";
const PROOF_SERVER_URL = process.env.MIDNIGHT_PROOF_SERVER_URL ?? "http://localhost:6300";
const WALLET_ADDRESS = process.env.MIDNIGHT_WALLET_ADDRESS ?? "TODO-your-wallet-address";
// Directory where `compactc` wrote the ZK artifacts (keys/proving data)
// for commit.compact - matches CompiledFileAssets path used in the
// deploy/commit scripts.
const ZK_CONFIG_DIR = "../build/commit";

export async function createProviders(): Promise<MidnightProviders<"commit" | "get_latest">> {
  setNetworkId("testnet");

  const zkConfigProvider = new NodeZkConfigProvider<"commit" | "get_latest">(ZK_CONFIG_DIR);

  const privateStateProvider = levelPrivateStateProvider<string>({
    privateStoragePasswordProvider: () => process.env.MIDNIGHT_WALLET_PASSWORD ?? "TODO-set-a-real-password",
    accountId: WALLET_ADDRESS,
  });

  const publicDataProvider = indexerPublicDataProvider(INDEXER_QUERY_URL, INDEXER_WS_URL);

  const proofProvider = httpClientProofProvider(PROOF_SERVER_URL, zkConfigProvider);

  // walletProvider + midnightProvider: these come from an actual
  // connected wallet (Lace extension, or a programmatic HDWallet built
  // from a seed/mnemonic). This is the one part that's genuinely
  // environment-specific and can't be filled in generically here -
  // follow the "Set up the wallet" section of Midnight's Counter CLI
  // tutorial (docs.midnight.network/tutorials/counter/counter-cli) and
  // paste the resulting walletProvider/midnightProvider pair in below.
  // Left as TODOs rather than faked, so this doesn't silently pass a
  // broken wallet into a real transaction.
  throw new Error(
    "TODO: wire up walletProvider and midnightProvider from a connected " +
    "wallet before calling createProviders() for real. See the comment above."
  );

  // Once wallet setup is added, return looks like:
  // return { privateStateProvider, publicDataProvider, zkConfigProvider, proofProvider, walletProvider, midnightProvider };
}

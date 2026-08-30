/**
 * providers.ts
 *
 * Builds the Midnight provider bundle. Reliability / hygiene fixes:
 *   - no `as any` on the wallet-facade configuration (M-6);
 *   - network id comes from env.ts, unified with the runtime id (M-10);
 *   - waits for the first non-empty wallet state before returning (M-7);
 *   - exponential-backoff sync poll with unref'd timers instead of a bare
 *     20s race that silently proceeded (M-8);
 *   - every subscription handle retained and torn down by `dispose()`,
 *     DB / provider handles closed (M-13);
 *   - MIDNIGHT_WALLET_PASSWORD required, seed strictly validated (M-9/M-11);
 *   - state logging reduced to a safe allowlist (M-12).
 */

import { setTimeout as delayPromise } from "node:timers/promises";
import { indexerPublicDataProvider } from "@midnight-ntwrk/midnight-js-indexer-public-data-provider";
import { httpClientProofProvider } from "@midnight-ntwrk/midnight-js-http-client-proof-provider";
import { levelPrivateStateProvider } from "@midnight-ntwrk/midnight-js-level-private-state-provider";
import { NodeZkConfigProvider } from "@midnight-ntwrk/midnight-js-node-zk-config-provider";
import type {
  MidnightProviders,
  WalletProvider,
  MidnightProvider,
} from "@midnight-ntwrk/midnight-js-types";
import { HDWallet, Roles } from "@midnight-ntwrk/wallet-sdk-hd";
import { WalletFacade, type BalancingRecipe } from "@midnight-ntwrk/wallet-sdk-facade";
import { ShieldedWallet } from "@midnight-ntwrk/wallet-sdk-shielded";
import { UnshieldedWallet } from "@midnight-ntwrk/wallet-sdk-unshielded-wallet";
import { DustWallet } from "@midnight-ntwrk/wallet-sdk-dust-wallet";
import type { TotalCostParameters } from "@midnight-ntwrk/wallet-sdk-dust-wallet/v1";
import {
  ZswapSecretKeys,
  DustSecretKey,
  LedgerParameters,
  signingKeyFromBip340,
  signData,
} from "@midnight-ntwrk/ledger-v8";

import {
  FACADE_NETWORK_ID,
  INDEXER_HTTP_URL,
  INDEXER_WS_URL,
  PROOF_SERVER_URL,
  RUNTIME_NETWORK_ID,
  ZK_CONFIG_DIR,
  applyRuntimeNetworkId,
  loadSeed,
  requireWalletPassword,
} from "./env.js";

type CircuitId = "commit" | "get_latest";

/** The exact type WalletFacade.init expects for its `configuration` field. */
type WalletFacadeConfig = Parameters<typeof WalletFacade.init>[0]["configuration"];

/** Minimal shape of an RxJS Subscription (avoids a hard rxjs dep here). */
interface Unsubscribable {
  unsubscribe(): void;
}

const sleepUnref = (ms: number): Promise<void> =>
  delayPromise(ms, undefined, { ref: false });

const FIRST_STATE_TIMEOUT_MS = Number(
  process.env.MIDNIGHT_FIRST_STATE_TIMEOUT_MS ?? 60_000,
);
const SYNC_DEADLINE_MS = Number(process.env.MIDNIGHT_SYNC_TIMEOUT_MS ?? 180_000);

// L-6: configurable fee margin + post-submit inclusion polling.
const FEE_BLOCKS_MARGIN = Number(process.env.MIDNIGHT_FEE_BLOCKS_MARGIN ?? 10);
const TX_CONFIRM_TIMEOUT_MS = Number(
  process.env.MIDNIGHT_TX_CONFIRM_TIMEOUT_MS ?? 120_000,
);
const TX_CONFIRM_INTERVAL_MS = Number(
  process.env.MIDNIGHT_TX_CONFIRM_INTERVAL_MS ?? 3_000,
);

interface SafeWalletState {
  address: string;
  coinPublicKey: string;
  encryptionPublicKey: string;
  syncHeight: string | number | null;
}

/** Pull only non-secret, loggable fields out of the wallet state (M-12). */
function pickSafeState(state: unknown): SafeWalletState {
  const s = (state ?? {}) as Record<string, any>;
  return {
    address: s.unshielded?.address ?? s.address ?? "",
    coinPublicKey: s.shielded?.coinPublicKey ?? "",
    encryptionPublicKey: s.shielded?.encryptionPublicKey ?? "",
    syncHeight:
      s.syncProgress?.syncedIndex ??
      s.syncProgress?.syncedHeight ??
      s.shielded?.syncProgress?.syncedHeight ??
      s.syncHeight ??
      null,
  };
}

function deriveKeys(seed: Uint8Array) {
  const seedResult = HDWallet.fromSeed(seed);
  if (seedResult.type === "seedError") {
    throw new Error(`Failed to derive HD wallet: ${seedResult.error}`);
  }
  const account = seedResult.hdWallet.selectAccount(0);
  const night = account.selectRole(Roles.NightExternal).deriveKeyAt(0);
  const zswap = account.selectRole(Roles.Zswap).deriveKeyAt(0);
  const dust = account.selectRole(Roles.Dust).deriveKeyAt(0);
  seedResult.hdWallet.clear();

  if (
    night.type !== "keyDerived" ||
    zswap.type !== "keyDerived" ||
    dust.type !== "keyDerived"
  ) {
    throw new Error("HD key derivation out of bounds for account 0, index 0");
  }

  const derived = {
    zswapSecretKeys: ZswapSecretKeys.fromSeed(zswap.key),
    dustSecretKey: DustSecretKey.fromSeed(dust.key),
    nightSigningKey: signingKeyFromBip340(night.key),
  };

  // L-10: wipe the raw per-role key bytes now that the SDK key objects
  // hold what they need. (nightSigningKey is a string and cannot be
  // zeroed - keep its lifetime as short as possible downstream.)
  for (const k of [night.key, zswap.key, dust.key]) {
    if (k instanceof Uint8Array) k.fill(0);
  }

  return derived;
}

/** Exponential-backoff sync poll. Fails closed unless MIDNIGHT_ALLOW_UNSYNCED=1. */
async function waitForSyncedWithBackoff(facade: WalletFacade): Promise<void> {
  const start = Date.now();
  let attempt = 0;
  let backoff = 500;

  while (Date.now() - start < SYNC_DEADLINE_MS) {
    const remaining = SYNC_DEADLINE_MS - (Date.now() - start);
    try {
      await Promise.race([
        facade.waitForSyncedState(),
        (async () => {
          await sleepUnref(Math.min(remaining, 30_000));
          throw new Error("sync attempt window elapsed");
        })(),
      ]);
      console.log(`Wallet synced after ${Math.round((Date.now() - start) / 1000)}s.`);
      return;
    } catch (err) {
      attempt += 1;
      console.log(
        `Wallet not synced (attempt ${attempt}: ${(err as Error).message}); ` +
          `retrying in ${backoff}ms`,
      );
      await sleepUnref(backoff);
      backoff = Math.min(backoff * 2, 15_000);
    }
  }

  if (process.env.MIDNIGHT_ALLOW_UNSYNCED === "1") {
    console.warn(
      `WARNING: wallet did not sync within ${SYNC_DEADLINE_MS}ms; proceeding ` +
        `because MIDNIGHT_ALLOW_UNSYNCED=1 (fees / coin selection may be wrong).`,
    );
    return;
  }
  throw new Error(
    `wallet did not reach synced state within ${SYNC_DEADLINE_MS}ms; raise ` +
      `MIDNIGHT_SYNC_TIMEOUT_MS or set MIDNIGHT_ALLOW_UNSYNCED=1 to override`,
  );
}

async function buildWalletFacade(seed: Uint8Array, subs: Unsubscribable[]) {
  const { zswapSecretKeys, dustSecretKey, nightSigningKey } = deriveKeys(seed);

  const costParameters: TotalCostParameters = { feeBlocksMargin: FEE_BLOCKS_MARGIN };
  const sharedConfig = {
    networkId: FACADE_NETWORK_ID,
    indexerClientConnection: {
      indexerHttpUrl: INDEXER_HTTP_URL,
      indexerWsUrl: INDEXER_WS_URL,
    },
    costParameters,
    provingServerUrl: PROOF_SERVER_URL,
  } satisfies WalletFacadeConfig;

  const dustParameters = LedgerParameters.initialParameters().dust;

  const facade = await WalletFacade.init({
    configuration: sharedConfig,
    shielded: (config) => ShieldedWallet(config).startWithSeed(seed),
    unshielded: (config) => {
      const cls = UnshieldedWallet(config);
      return cls.startEmpty(cls);
    },
    dust: (config) => DustWallet(config).startWithSeed(seed, dustParameters),
  });

  // One retained subscription feeds: the provider's public-key getters,
  // the redacted logger, and the "first non-empty state" gate.
  const latest: { value: unknown } = { value: undefined };
  let signalPopulated: (() => void) | undefined;
  subs.push(
    facade.state().subscribe((s: unknown) => {
      latest.value = s;
      const safe = pickSafeState(s);
      if (safe.coinPublicKey && safe.encryptionPublicKey) signalPopulated?.();
    }),
  );

  // M-7: block until coinPublicKey / encryptionPublicKey are populated.
  await new Promise<void>((resolve, reject) => {
    if (pickSafeState(latest.value).coinPublicKey) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      signalPopulated = undefined;
      reject(
        new Error(
          `wallet coin/encryption public key not populated within ${FIRST_STATE_TIMEOUT_MS}ms`,
        ),
      );
    }, FIRST_STATE_TIMEOUT_MS);
    timer.unref?.();
    signalPopulated = () => {
      clearTimeout(timer);
      signalPopulated = undefined;
      resolve();
    };
  });

  console.log("WALLET:", JSON.stringify(pickSafeState(latest.value)));

  await waitForSyncedWithBackoff(facade);

  return { facade, latest, zswapSecretKeys, dustSecretKey, nightSigningKey };
}

function makeWalletProvider(
  facade: WalletFacade,
  latest: { value: unknown },
  zswapSecretKeys: ZswapSecretKeys,
  dustSecretKey: DustSecretKey,
  nightSigningKey: string,
): WalletProvider {
  return {
    async balanceTx(tx, ttl) {
      const recipe: BalancingRecipe = await facade.balanceUnboundTransaction(
        tx as never,
        { shieldedSecretKeys: zswapSecretKeys, dustSecretKey },
        { ttl: ttl ?? new Date(Date.now() + 10 * 60 * 1000) },
      );
      const signed = await facade.signRecipe(recipe, (data) =>
        signData(nightSigningKey, data),
      );
      return facade.finalizeRecipe(signed);
    },
    getCoinPublicKey() {
      return pickSafeState(latest.value).coinPublicKey;
    },
    getEncryptionPublicKey() {
      return pickSafeState(latest.value).encryptionPublicKey;
    },
  };
}

/** Best-effort poll that a submitted tx has been indexed (L-6). */
async function confirmInclusion(publicDataProvider: unknown, txId: string): Promise<void> {
  const w = publicDataProvider as {
    watchForTxData?: (id: string) => Promise<unknown>;
    queryTxData?: (id: string) => Promise<unknown | null>;
  };

  if (typeof w.watchForTxData === "function") {
    await Promise.race([
      w.watchForTxData(txId),
      (async () => {
        await sleepUnref(TX_CONFIRM_TIMEOUT_MS);
        throw new Error(`not indexed within ${TX_CONFIRM_TIMEOUT_MS}ms`);
      })(),
    ]);
    return;
  }

  if (typeof w.queryTxData === "function") {
    const deadline = Date.now() + TX_CONFIRM_TIMEOUT_MS;
    while (Date.now() < deadline) {
      const data = await w.queryTxData(txId).catch(() => null);
      if (data) return;
      await sleepUnref(TX_CONFIRM_INTERVAL_MS);
    }
    throw new Error(`not indexed within ${TX_CONFIRM_TIMEOUT_MS}ms`);
  }

  console.warn(
    "tx confirmation: publicDataProvider exposes no watch/query method; skipping inclusion poll",
  );
}

function makeMidnightProvider(
  facade: WalletFacade,
  publicDataProvider: unknown,
): MidnightProvider {
  return {
    async submitTx(tx) {
      const txId = await facade.submitTransaction(tx);
      const short = String(txId).slice(0, 16);
      try {
        await confirmInclusion(publicDataProvider, String(txId));
        console.log(`tx ${short}… confirmed on the indexer`);
      } catch (err) {
        console.warn(
          `tx ${short}… submitted but not confirmed (${(err as Error).message}); ` +
            `bump MIDNIGHT_FEE_BLOCKS_MARGIN and retry if it never lands`,
        );
      }
      return txId;
    },
  };
}

export interface ProviderBundle {
  providers: MidnightProviders<CircuitId>;
  /** Unsubscribe every retained handle, close DB / provider handles. */
  dispose: () => Promise<void>;
}

export async function createProviders(): Promise<ProviderBundle> {
  applyRuntimeNetworkId();
  console.log(`Network: ${RUNTIME_NETWORK_ID} | indexer: ${INDEXER_HTTP_URL}`);
  requireWalletPassword(); // fail fast before any network work

  const subs: Unsubscribable[] = [];
  const zkConfigProvider = new NodeZkConfigProvider<CircuitId>(ZK_CONFIG_DIR);
  const privateStateProvider = levelPrivateStateProvider<string>({
    privateStoragePasswordProvider: () => requireWalletPassword(),
    accountId: process.env.MIDNIGHT_WALLET_LABEL ?? "firewall-audit-committer",
  });
  const publicDataProvider = indexerPublicDataProvider(
    INDEXER_HTTP_URL,
    INDEXER_WS_URL,
  );
  const proofProvider = httpClientProofProvider(PROOF_SERVER_URL, zkConfigProvider);

  const seed = loadSeed();
  const { facade, latest, zswapSecretKeys, dustSecretKey, nightSigningKey } =
    await buildWalletFacade(seed, subs);
  seed.fill(0); // wipe the raw seed once the facade + keys are built

  const walletProvider = makeWalletProvider(
    facade,
    latest,
    zswapSecretKeys,
    dustSecretKey,
    nightSigningKey,
  );
  const midnightProvider = makeMidnightProvider(facade, publicDataProvider);

  let disposed = false;
  const dispose = async (): Promise<void> => {
    if (disposed) return;
    disposed = true;
    for (const s of subs.splice(0)) {
      try {
        s.unsubscribe();
      } catch {
        /* ignore */
      }
    }
    const closables = [
      facade,
      publicDataProvider,
      privateStateProvider,
    ] as unknown as Array<{ close?: () => unknown }>;
    for (const c of closables) {
      try {
        await c.close?.();
      } catch {
        /* ignore */
      }
    }
  };

  return {
    providers: {
      privateStateProvider,
      publicDataProvider,
      zkConfigProvider,
      proofProvider,
      walletProvider,
      midnightProvider,
    },
    dispose,
  };
}

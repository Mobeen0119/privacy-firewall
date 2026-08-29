import { readFileSync } from "fs";
import path from "node:path";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
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
import {
  WalletFacade,
  type BalancingRecipe,
} from "@midnight-ntwrk/wallet-sdk-facade";
import { ShieldedWallet } from "@midnight-ntwrk/wallet-sdk-shielded";
import { UnshieldedWallet } from "@midnight-ntwrk/wallet-sdk-unshielded-wallet";
import { DustWallet } from "@midnight-ntwrk/wallet-sdk-dust-wallet";
import type { TotalCostParameters } from "@midnight-ntwrk/wallet-sdk-dust-wallet/v1";
import { NetworkId } from "@midnight-ntwrk/wallet-sdk-abstractions";
import {
  ZswapSecretKeys,
  DustSecretKey,
  LedgerParameters,
  signingKeyFromBip340,
  signData,
} from "@midnight-ntwrk/ledger-v8";

const INDEXER_HTTP_URL =
  process.env.MIDNIGHT_INDEXER_URL ??
  "https://indexer.preview.midnight.network/api/v4/graphql";

const INDEXER_WS_URL =
  process.env.MIDNIGHT_INDEXER_WS_URL ??
  "wss://indexer.preview.midnight.network/api/v4/graphql/ws";

const PROOF_SERVER_URL =
  process.env.MIDNIGHT_PROOF_SERVER_URL ?? "http://127.0.0.1:6300";

const ZK_CONFIG_DIR = path.resolve("build/commit");

function loadSeed(): Uint8Array {
  const seedHex = process.env.MIDNIGHT_WALLET_SEED;

  if (seedHex) {
    return new Uint8Array(Buffer.from(seedHex, "hex"));
  }

  const seedFile =
    process.env.MIDNIGHT_WALLET_SEED_FILE ?? "seed.txt";

  return new Uint8Array(
    Buffer.from(readFileSync(seedFile, "utf-8").trim(), "hex"),
  );
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
    throw new Error("HD key derivation out of bounds");
  }

  return {
    zswapSecretKeys: ZswapSecretKeys.fromSeed(zswap.key),
    dustSecretKey: DustSecretKey.fromSeed(dust.key),
    nightSigningKey: signingKeyFromBip340(night.key),
  };
}

async function buildWalletFacade(seed: Uint8Array) {
  const { zswapSecretKeys, dustSecretKey, nightSigningKey } =
    deriveKeys(seed);

  const costParameters: TotalCostParameters = {
    feeBlocksMargin: 10,
  };

  console.log("INDEXER HTTP:", INDEXER_HTTP_URL);
  console.log("INDEXER WS:", INDEXER_WS_URL);
  console.log("NETWORK:", NetworkId.NetworkId.Preview);

  const sharedConfig = {
    networkId: NetworkId.NetworkId.Preview,
    indexerClientConnection: {
      indexerHttpUrl: INDEXER_HTTP_URL,
      indexerWsUrl: INDEXER_WS_URL,
    },
    costParameters,
    provingServerUrl: PROOF_SERVER_URL,
  };

  const dustParameters =
    LedgerParameters.initialParameters().dust;

  const facade = await WalletFacade.init({
    configuration: sharedConfig as any,
    shielded: (config) =>
      ShieldedWallet(config).startWithSeed(seed),
    unshielded: (config) => {
      const cls = UnshieldedWallet(config);
      return cls.startEmpty(cls);
    },
    dust: (config) =>
      DustWallet(config).startWithSeed(seed, dustParameters),
  });

  console.log("FACADE CREATED");

  facade.state().subscribe((s) => {
    console.log(
      "WALLET STATE:",
      JSON.stringify(
        s,
        (_k, v) =>
          typeof v === "bigint" ? v.toString() : v,
      ),
    );
  });

await Promise.race([
  facade.waitForSyncedState(),
  new Promise((resolve) => setTimeout(resolve, 20000)),
]);
console.log("Proceeding (synced or 20s timeout reached).");
console.log("Proceeding (synced or 20s timeout reached).");
  return {
    facade,
    zswapSecretKeys,
    dustSecretKey,
    nightSigningKey,
  };
}

function makeWalletProvider(
  facade: WalletFacade,
  zswapSecretKeys: ZswapSecretKeys,
  dustSecretKey: DustSecretKey,
  nightSigningKey: string,
): WalletProvider {
  let latest = {
    coinPublicKey: "",
    encryptionPublicKey: "",
  };

  facade.state().subscribe((s) => {
    latest = {
      coinPublicKey: s.shielded.coinPublicKey.toHexString(),
      encryptionPublicKey:
        s.shielded.encryptionPublicKey.toHexString(),
    };
  });

  return {
    async balanceTx(tx, ttl) {
      const recipe: BalancingRecipe =
        await facade.balanceUnboundTransaction(
          tx as any,
          {
            shieldedSecretKeys: zswapSecretKeys,
            dustSecretKey,
          },
          {
            ttl:
              ttl ??
              new Date(Date.now() + 10 * 60 * 1000),
          },
        );

      const signed = await facade.signRecipe(
        recipe,
        (data) => signData(nightSigningKey, data),
      );

      return facade.finalizeRecipe(signed);
    },

    getCoinPublicKey() {
      return latest.coinPublicKey;
    },

    getEncryptionPublicKey() {
      return latest.encryptionPublicKey;
    },
  };
}

function makeMidnightProvider(
  facade: WalletFacade,
): MidnightProvider {
  return {
    async submitTx(tx) {
      return facade.submitTransaction(tx);
    },
  };
}

export async function createProviders(): Promise<
  MidnightProviders<"commit" | "get_latest">
> {
  setNetworkId("preview");

  const zkConfigProvider =
    new NodeZkConfigProvider<"commit" | "get_latest">(
      ZK_CONFIG_DIR,
    );

  const privateStateProvider =
    levelPrivateStateProvider<string>({
      privateStoragePasswordProvider: () =>
        process.env.MIDNIGHT_WALLET_PASSWORD ??
        "a-strong-local-dev-password-1",
      accountId:
        process.env.MIDNIGHT_WALLET_LABEL ??
        "firewall-audit-committer",
    });

  const publicDataProvider = indexerPublicDataProvider(
    INDEXER_HTTP_URL,
    INDEXER_WS_URL,
  );

  const proofProvider = httpClientProofProvider(
    PROOF_SERVER_URL,
    zkConfigProvider,
  );

  const seed = loadSeed();

  const {
    facade,
    zswapSecretKeys,
    dustSecretKey,
    nightSigningKey,
  } = await buildWalletFacade(seed);

  const walletProvider = makeWalletProvider(
    facade,
    zswapSecretKeys,
    dustSecretKey,
    nightSigningKey,
  );

  const midnightProvider = makeMidnightProvider(facade);

  return {
    privateStateProvider,
    publicDataProvider,
    zkConfigProvider,
    proofProvider,
    walletProvider,
    midnightProvider,
  };
}

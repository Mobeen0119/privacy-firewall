/**
 * Off-chain harness (audit finding M-16). Run: `npm test`
 * (needs `npm ci` first - it imports the real scripts/ modules).
 *
 * Circuit-level tests (owner gate, epoch monotonicity, accumulator
 * chaining) need `compact compile` + a Midnight local env; those cases
 * are specified in test/contract-harness.md.
 */

import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, rmSync, statSync } from "node:fs";

process.env.MIDNIGHT_WALLET_PASSWORD ??= "test-password-123";

const { loadContractSigningKey, signingAuthorityKeyId, writeDeploymentRecord, readDeploymentRecord, DEPLOYMENT_PATH } =
  await import("../scripts/deployment.js");
const env = await import("../scripts/env.js");

const SEED_A = "a".repeat(64);
const SEED_B = "b".repeat(64);

test("contract signing key is deterministic from the seed and 64 hex", () => {
  process.env.MIDNIGHT_WALLET_SEED = SEED_A;
  delete process.env.MIDNIGHT_CONTRACT_SIGNING_KEY;
  const k1 = loadContractSigningKey();
  const k2 = loadContractSigningKey();
  assert.match(k1, /^[0-9a-f]{64}$/);
  assert.equal(k1, k2);
  process.env.MIDNIGHT_WALLET_SEED = SEED_B;
  assert.notEqual(loadContractSigningKey(), k1);
});

test("managed signing key overrides derivation and is validated", () => {
  process.env.MIDNIGHT_CONTRACT_SIGNING_KEY = "F".repeat(64);
  assert.equal(loadContractSigningKey(), "f".repeat(64));
  process.env.MIDNIGHT_CONTRACT_SIGNING_KEY = "xyz";
  assert.throws(() => loadContractSigningKey(), /64 hex/);
  delete process.env.MIDNIGHT_CONTRACT_SIGNING_KEY;
});

test("signingAuthorityKeyId is stable and key-dependent", () => {
  const a = signingAuthorityKeyId("00".repeat(32));
  assert.equal(a, signingAuthorityKeyId("00".repeat(32)));
  assert.notEqual(a, signingAuthorityKeyId("01" + "00".repeat(31)));
});

test("seed validation rejects non-64-hex", () => {
  process.env.MIDNIGHT_WALLET_SEED = "nothex";
  assert.throws(() => env.loadSeed(), /64/);
  process.env.MIDNIGHT_WALLET_SEED = SEED_A;
  assert.equal(env.loadSeed().length, 32);
});

test("MIDNIGHT_WALLET_PASSWORD is required (no default)", () => {
  const saved = process.env.MIDNIGHT_WALLET_PASSWORD;
  delete process.env.MIDNIGHT_WALLET_PASSWORD;
  assert.throws(() => env.requireWalletPassword(), /required/);
  process.env.MIDNIGHT_WALLET_PASSWORD = saved;
});

test("deployment.json write is 0600 and round-trips", { skip: existsSync(DEPLOYMENT_PATH) ? "real deployment.json present" : false }, () => {
  const rec = {
    network: "preview",
    networkId: "TestNet",
    contractAddress: "0200abcd",
    deployTxHash: "deadbeef",
    ownerPublicKey: "ab".repeat(32),
    signingAuthorityKeyId: "cd".repeat(32),
    compiledContractSha256: "ef".repeat(32),
    deployedAt: new Date().toISOString(),
  };
  writeDeploymentRecord(rec);
  try {
    const mode = statSync(DEPLOYMENT_PATH).mode & 0o777;
    assert.equal(mode, 0o600);
    assert.deepEqual(readDeploymentRecord(), rec);
  } finally {
    rmSync(DEPLOYMENT_PATH, { force: true });
  }
});

test("readDeploymentRecord rejects a record missing required fields", { skip: existsSync(DEPLOYMENT_PATH) ? "real deployment.json present" : false }, () => {
  writeDeploymentRecord({
    network: "",
    networkId: "TestNet",
    contractAddress: "0200abcd",
    deployTxHash: "x",
    ownerPublicKey: "y",
    signingAuthorityKeyId: "z",
    compiledContractSha256: "w",
    deployedAt: "t",
  } as never);
  try {
    assert.throws(() => readDeploymentRecord(), /missing required field 'network'/);
  } finally {
    rmSync(DEPLOYMENT_PATH, { force: true });
  }
});

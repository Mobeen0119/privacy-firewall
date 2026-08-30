/**
 * run_pipeline.ts
 *
 * audit -> sign -> commit -> verify, end to end, against EXISTING log
 * data. It never generates sample data - use `npm run demo` for that
 * (audit finding M-5).
 *
 * Stages are explicit and produce distinct exit codes (M-17):
 *   10 PRE_COMMIT   - log / chain / sign / deployment problems
 *   20 COMMIT       - the on-chain commit tx failed (nothing committed)
 *   30 POST_COMMIT  - commit landed but verification failed (investigate!)
 *
 * All paths are absolute (H-8); the commit runs in-process (H-8); the
 * committed value is read back from the indexer and checked (M-4).
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";
import { commitToChain } from "./commit_to_chain.js";
import { readDeploymentRecord } from "./deployment.js";
import { readOnchainState } from "./onchain.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const AUDIT_DIR = path.resolve(HERE, "../audit");
const LOG_FILE = path.join(AUDIT_DIR, "audit_log.jsonl");
const ROOT_HASH_FILE = path.join(AUDIT_DIR, "root_hash.txt");
const HEX64 = /^[0-9a-fA-F]{64}$/;
const HEX128 = /^[0-9a-fA-F]{128}$/;

export enum Stage {
  PreCommit = "PRE_COMMIT",
  Commit = "COMMIT",
  PostCommit = "POST_COMMIT",
}

const EXIT_CODE: Record<Stage, number> = {
  [Stage.PreCommit]: 10,
  [Stage.Commit]: 20,
  [Stage.PostCommit]: 30,
};

export class StageError extends Error {
  readonly stage: Stage;
  constructor(stage: Stage, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.stage = stage;
    this.name = "StageError";
  }
}

function py(script: string, args: string[]): void {
  execFileSync("python3", [path.join(AUDIT_DIR, script), ...args], {
    stdio: "inherit",
    cwd: AUDIT_DIR,
  });
}

function pyCapture(script: string, args: string[]): string {
  return execFileSync("python3", [path.join(AUDIT_DIR, script), ...args], {
    cwd: AUDIT_DIR,
  })
    .toString()
    .trim();
}

export async function runPipeline(): Promise<void> {
  // ---------------------------------------------------------------- PRE_COMMIT
  if (!existsSync(LOG_FILE) || statSync(LOG_FILE).size === 0) {
    throw new StageError(
      Stage.PreCommit,
      `no audit log at ${LOG_FILE}. Put the real log there, or run 'npm run demo' for sample data.`,
    );
  }

  let deployment: ReturnType<typeof readDeploymentRecord>;
  try {
    deployment = readDeploymentRecord();
  } catch (err) {
    throw new StageError(Stage.PreCommit, `deployment.json unusable: ${(err as Error).message}`, {
      cause: err,
    });
  }

  let rootHash: string;
  try {
    console.log("1/5 building hash chain...");
    py("hash_chain.py", []);
    rootHash = readFileSync(ROOT_HASH_FILE, "utf-8").trim();
    if (!HEX64.test(rootHash)) {
      throw new Error(`hash_chain.py produced an invalid root hash: ${JSON.stringify(rootHash)}`);
    }
  } catch (err) {
    throw new StageError(Stage.PreCommit, `hash chain build failed: ${(err as Error).message}`, {
      cause: err,
    });
  }

  let epoch: bigint;
  try {
    console.log("2/5 reading on-chain epoch...");
    const pre = await readOnchainState(deployment.contractAddress);
    epoch = pre ? pre.commitCount : 0n;
    console.log(`   epoch = ${epoch}`);
  } catch (err) {
    throw new StageError(Stage.PreCommit, `could not read on-chain epoch: ${(err as Error).message}`, {
      cause: err,
    });
  }

  let signature: string;
  try {
    console.log("3/5 signing root hash (context-bound)...");
    signature = pyCapture("sign.py", [
      "sign",
      rootHash,
      deployment.network,
      deployment.contractAddress,
      String(epoch),
    ]);
    if (!HEX128.test(signature)) {
      throw new Error(`sign.py produced an unexpected signature: ${JSON.stringify(signature)}`);
    }
  } catch (err) {
    throw new StageError(Stage.PreCommit, `signing failed: ${(err as Error).message}`, {
      cause: err,
    });
  }

  // -------------------------------------------------------------------- COMMIT
  console.log("4/5 committing to chain (in-process)...");
  try {
    const txHash = await commitToChain({ epoch });
    console.log(`   commit tx: ${txHash}`);
  } catch (err) {
    throw new StageError(
      Stage.Commit,
      `on-chain commit failed - nothing was committed: ${(err as Error).message}`,
      { cause: err },
    );
  }

  // --------------------------------------------------------------- POST_COMMIT
  console.log("5/5 verifying (chain + signature + on-chain state)...");
  try {
    const post = await readOnchainState(deployment.contractAddress);
    if (!post) throw new Error("contract state not found on the indexer after commit");
    if (post.lastRoot.toLowerCase() !== rootHash.toLowerCase()) {
      throw new Error(
        `on-chain lastRoot ${post.lastRoot} != committed root ${rootHash}`,
      );
    }
    if (post.commitCount !== epoch + 1n) {
      throw new Error(`on-chain commitCount ${post.commitCount} != expected ${epoch + 1n}`);
    }

    py("verify.py", [
      "audit_log.jsonl",
      rootHash,
      signature,
      "--network",
      deployment.network,
      "--contract",
      deployment.contractAddress,
      "--epoch",
      String(epoch),
      "--onchain-root",
      post.lastRoot,
      "--require-onchain",
    ]);
  } catch (err) {
    throw new StageError(
      Stage.PostCommit,
      `COMMIT LANDED but post-commit verification failed - investigate the on-chain value: ${(err as Error).message}`,
      { cause: err },
    );
  }

  console.log("\nPipeline OK.");
}

function isMain(): boolean {
  const entry = process.argv[1];
  return !!entry && import.meta.url === pathToFileURL(entry).href;
}

if (isMain()) {
  runPipeline()
    .then(() => process.exit(0))
    .catch((err: unknown) => {
      if (err instanceof StageError) {
        console.error(`\n[${err.stage}] ${err.message}`);
        process.exit(EXIT_CODE[err.stage] ?? 1);
      }
      console.error("\nPipeline failed (unclassified):", err);
      process.exit(1);
    });
}

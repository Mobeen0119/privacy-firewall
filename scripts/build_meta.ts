/**
 * build_meta.ts
 *
 * Leaf module (no SDK imports) for the contract-build freshness check
 * (audit finding M-14). Kept dependency-free so `npm run compile` can use
 * it without pulling in @midnight-ntwrk/*.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";

/** File `npm run compile` writes into the build dir. */
export const BUILD_STAMP = ".source-sha256";

export function sha256File(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

/**
 * Refuse to deploy / commit against a build dir that is missing or stale
 * relative to the contract source.
 */
export function assertBuildFresh(contractSrc: string, buildDir: string): void {
  const stampPath = path.join(buildDir, BUILD_STAMP);
  let stamp: string;
  try {
    stamp = readFileSync(stampPath, "utf-8").trim();
  } catch {
    throw new Error(
      `${buildDir} is missing or was not produced by 'npm run compile' ` +
        `(no ${BUILD_STAMP}); run 'npm run compile'`,
    );
  }
  const actual = sha256File(contractSrc);
  if (stamp.toLowerCase() !== actual.toLowerCase()) {
    throw new Error(
      `build output is stale: ${BUILD_STAMP}=${stamp.slice(0, 12)}… but ` +
        `commit.compact now hashes to ${actual.slice(0, 12)}…; run 'npm run compile'`,
    );
  }
}

/**
 * compile.ts
 *
 * Wraps `compact compile` and writes build/commit/.source-sha256 so
 * deploy / commit can verify the build matches the source (audit M-14).
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BUILD_STAMP, sha256File } from "./build_meta.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, "../contract/commit.compact");
const OUT = path.resolve(HERE, "../build/commit");

execFileSync("compact", ["compile", SRC, OUT], { stdio: "inherit" });

mkdirSync(OUT, { recursive: true });
const digest = sha256File(SRC);
writeFileSync(path.join(OUT, BUILD_STAMP), digest + "\n", { mode: 0o644 });

console.log(`compiled ${path.relative(process.cwd(), SRC)} -> ${path.relative(process.cwd(), OUT)}`);
console.log(`${BUILD_STAMP} = ${digest}`);

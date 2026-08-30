/**
 * demo.ts  (npm run demo)
 *
 * Generates sample audit data, then runs the standard pipeline. This is
 * the ONLY entry point that fabricates a log - the pipeline itself never
 * does (audit finding M-5).
 */

import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { runPipeline, StageError } from "./run_pipeline.js";

const AUDIT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../audit");

console.log("demo: generating fake audit log...");
execFileSync("python3", [path.join(AUDIT_DIR, "fake_audit_generator.py")], {
  stdio: "inherit",
  cwd: AUDIT_DIR,
});

runPipeline()
  .then(() => process.exit(0))
  .catch((err: unknown) => {
    if (err instanceof StageError) {
      console.error(`\n[${err.stage}] ${err.message}`);
      process.exit(1);
    }
    console.error("\ndemo failed:", err);
    process.exit(1);
  });

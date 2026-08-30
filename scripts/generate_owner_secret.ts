/**
 * generate_owner_secret.ts
 *
 * Creates the 32-byte owner authority secret for the commit.compact
 * contract. Its domain-separated hash (see `ownerPublicKey`) becomes the
 * on-chain `owner`; whoever holds this file can call `commit`.
 *
 *   npm run generate-owner-secret            # -> audit/firewall_owner_secret.key
 *   npm run generate-owner-secret /path/key  # -> custom path
 */

import { chmodSync, existsSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const out =
  process.argv[2] ?? path.resolve(HERE, "../audit/firewall_owner_secret.key");

if (existsSync(out) && process.argv[3] !== "--force") {
  console.error(
    `${out} already exists. Overwriting rotates the owner and makes the ` +
      `deployed contract unusable until redeployed. Pass --force to proceed.`,
  );
  process.exit(1);
}

const secret = randomBytes(32).toString("hex");
writeFileSync(out, secret + "\n", { mode: 0o600 });
chmodSync(out, 0o600);

console.log(`Owner secret (32 bytes) written to ${out} (mode 0600).`);
console.log("Keep it out of version control (see .gitignore).");
console.log(
  "Deployer needs this file or MIDNIGHT_AUDIT_OWNER_PK; committer needs this file.",
);

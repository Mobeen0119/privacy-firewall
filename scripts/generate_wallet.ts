import { writeFileSync } from "fs";
import { generateRandomSeed } from "@midnight-ntwrk/wallet-sdk-hd";

const seed = generateRandomSeed();
const seedHex = Buffer.from(seed).toString("hex");

const outFile = process.argv[2] ?? "seed.txt";
writeFileSync(outFile, seedHex);
console.log(`Seed written to ${outFile}`);
console.log("Fund the address this seed derives via the Preview faucet:");
console.log("https://midnight-tmnight-preview.nethermind.dev/");

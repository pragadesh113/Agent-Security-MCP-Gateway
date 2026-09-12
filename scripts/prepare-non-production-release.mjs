import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const npm = process.platform === "win32" ? process.env.ComSpec : "npm";

function run(command) {
  const args = process.platform === "win32"
    ? ["/d", "/s", "/c", `npm run ${command}`]
    : ["run", command];
  execFileSync(npm, args, { cwd: root, stdio: "inherit" });
}

for (const command of [
  "build",
  "lint",
  "typecheck",
  "test",
  "test:integration",
  "validate:features",
  "verify:package-boundary",
  "dashboard:build",
  "sbom:generate",
  "deploy:verify:non-production",
  "release:manifest",
  "release:verify",
  "build:verify-reproducible"
]) {
  run(command);
}

execFileSync(npm, process.platform === "win32"
  ? ["/d", "/s", "/c", "npm audit --audit-level=high"]
  : ["audit", "--audit-level=high"], { cwd: root, stdio: "inherit" });

console.log("Non-production release preparation passed. No artifact was signed, published, or production-approved.");

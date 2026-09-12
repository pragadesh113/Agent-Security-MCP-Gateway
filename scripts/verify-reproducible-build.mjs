import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const command = process.platform === "win32" ? process.env.ComSpec : "npm";
const args = process.platform === "win32" ? ["/d", "/s", "/c", "npm run build"] : ["run", "build"];

function build() {
  execFileSync(command, args, { cwd: root, stdio: "inherit" });
}

async function snapshot() {
  const outputDir = path.join(root, "dist");
  const entries = (await readdir(outputDir, { recursive: true, withFileTypes: true }))
    .filter((entry) => entry.isFile())
    .map((entry) => path.relative(outputDir, path.join(entry.parentPath, entry.name)))
    .sort();
  const hashes = {};
  for (const entry of entries) {
    const bytes = await readFile(path.join(outputDir, entry));
    hashes[entry.replaceAll("\\", "/")] = createHash("sha256").update(bytes).digest("hex");
  }
  return hashes;
}

build();
const first = await snapshot();
build();
const second = await snapshot();
if (JSON.stringify(first) !== JSON.stringify(second)) {
  throw new Error("Generated build output is not reproducible");
}
console.log(`Reproducible build verified: ${Object.keys(first).length} generated files match.`);

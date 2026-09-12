import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { releaseInputFiles } from "./release-inputs.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(await readFile(path.join(root, "artifacts", "release-manifest.json"), "utf8"));
if (manifest.schemaVersion !== "1.0.0" || manifest.signed !== false || manifest.published !== false || manifest.productionApproved !== false) {
  throw new Error("Manifest is not an unsigned, unpublished, non-production manifest");
}
const expectedFiles = await releaseInputFiles(root);
const recordedFiles = Object.keys(manifest.files ?? {}).sort();
if (JSON.stringify(recordedFiles) !== JSON.stringify(expectedFiles)) {
  throw new Error("Manifest does not contain the exact required release input set");
}
for (const [relativePath, expected] of Object.entries(manifest.files ?? {})) {
  const actual = createHash("sha256").update(await readFile(path.join(root, relativePath))).digest("hex");
  if (actual !== expected) throw new Error(`Hash mismatch: ${relativePath}`);
}
if (manifest.dockerImage?.reference !== "agent-security-gateway:non-production" || typeof manifest.dockerImage?.localImageId !== "string" || !manifest.dockerImage.localImageId.startsWith("sha256:")) {
  throw new Error("Manifest requires the exact non-production image reference and a local image ID");
}
const actualImageId = execFileSync("docker", ["image", "inspect", manifest.dockerImage.reference, "--format", "{{.Id}}"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
if (actualImageId !== manifest.dockerImage.localImageId) throw new Error("Docker image ID mismatch");
console.log(`Release manifest verified: ${Object.keys(manifest.files).length} file hashes and local image identity match.`);

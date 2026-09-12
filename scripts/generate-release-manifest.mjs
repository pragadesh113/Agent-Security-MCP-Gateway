import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { releaseInputFiles } from "./release-inputs.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageJson = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const files = await releaseInputFiles(root);
const sha256 = async (relativePath) => {
  const bytes = await readFile(path.join(root, relativePath));
  return createHash("sha256").update(bytes).digest("hex");
};
const imageId = (() => {
  try {
    return execFileSync("docker", ["image", "inspect", "agent-security-gateway:non-production", "--format", "{{.Id}}"], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim() || null;
  } catch {
    return null;
  }
})();
if (imageId === null) {
  throw new Error("Release manifest generation requires the verified local non-production image");
}
const manifest = {
  schemaVersion: "1.0.0",
  package: { name: packageJson.name, version: packageJson.version, private: packageJson.private },
  files: Object.fromEntries(await Promise.all(files.map(async (file) => [file, await sha256(file)]))),
  dockerImage: { reference: "agent-security-gateway:non-production", localImageId: imageId },
  signed: false,
  published: false,
  productionApproved: false
};
await mkdir(path.join(root, "artifacts"), { recursive: true });
const output = path.join(root, "artifacts", "release-manifest.json");
await writeFile(output, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
console.log(`Release manifest generated at ${path.relative(root, output)}.`);

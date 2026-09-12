import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const command = process.platform === "win32" ? process.env.ComSpec : "npm";
const args = process.platform === "win32"
  ? ["/d", "/s", "/c", "npm sbom --package-lock-only --sbom-format=cyclonedx --sbom-type=application"]
  : ["sbom", "--package-lock-only", "--sbom-format=cyclonedx", "--sbom-type=application"];
const output = execFileSync(command, args, {
  cwd: root,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "inherit"]
});
const sbom = JSON.parse(output);
if (sbom.bomFormat !== "CycloneDX" || sbom.specVersion !== "1.5") {
  throw new Error("Unexpected SBOM format or specification version");
}
await mkdir(path.join(root, "artifacts"), { recursive: true });
const outputPath = path.join(root, "artifacts", "sbom.cdx.json");
await writeFile(outputPath, `${JSON.stringify(sbom, null, 2)}\n`, "utf8");
console.log(`CycloneDX SBOM generated at ${path.relative(root, outputPath)} (${sbom.components?.length ?? 0} components).`);

import { readdir } from "node:fs/promises";
import path from "node:path";

async function filesUnder(root, relativeDirectory) {
  const directory = path.join(root, relativeDirectory);
  const entries = await readdir(directory, { recursive: true, withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.relative(root, path.join(entry.parentPath, entry.name)).replaceAll("\\", "/"));
}

export async function releaseInputFiles(root) {
  const files = [
    "package.json",
    "package-lock.json",
    "tsconfig.json",
    ".npmignore",
    ".dockerignore",
    "Dockerfile.non-production",
    "compose.non-production.yml",
    "artifacts/sbom.cdx.json",
    ...(await filesUnder(root, "docs")).filter((file) => /\.(?:md|json)$/u.test(file)),
    ...(await filesUnder(root, "migrations")).filter((file) => file.endsWith(".sql")),
    ...(await filesUnder(root, "scripts")).filter((file) => /\.(?:mjs|mts)$/u.test(file)),
    ...(await filesUnder(root, "src")).filter((file) => file.endsWith(".ts")),
    ...(await filesUnder(root, "test")).filter((file) => file.endsWith(".ts"))
  ];
  return [...new Set(files)].sort();
}

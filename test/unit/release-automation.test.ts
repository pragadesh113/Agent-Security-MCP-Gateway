import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { releaseInputFiles } from "../../scripts/release-inputs.mjs";
import { validateFeatureList } from "../../scripts/validate-features.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

describe("non-production release inputs", () => {
  it("binds deployment automation, container configuration, and every source file", async () => {
    const files = await releaseInputFiles(root);
    expect(files).toEqual([...files].sort());
    expect(new Set(files).size).toBe(files.length);
    expect(files).toEqual(expect.arrayContaining([
      ".dockerignore",
      ".npmignore",
      "Dockerfile.non-production",
      "package.json",
      "package-lock.json",
      "tsconfig.json",
      "scripts/prepare-non-production-release.mjs",
      "scripts/verify-non-production-deployment.mjs",
      "scripts/verify-package-boundary.mjs",
      "scripts/generate-release-manifest.mjs",
      "scripts/verify-release-manifest.mjs",
      "scripts/validate-features.mjs",
      "scripts/validate-features.d.mts",
      "src/index.ts",
      "test/unit/release-automation.test.ts",
      "docs/featurelist.json",
      "migrations/0001_phase2_core.sql"
    ]));
    expect(files.filter((file) => file.startsWith("src/"))).not.toHaveLength(0);
    expect(files.filter((file) => file.startsWith("test/"))).not.toHaveLength(0);
    expect(files.some((file) => file.startsWith("phase-1/"))).toBe(false);
  });

  it("rejects a complete feature without exact completion evidence", async () => {
    const parsed: unknown = JSON.parse(
      await readFile(path.join(root, "docs", "featurelist.json"), "utf8")
    );
    const featureList = parsed as {
      features: Array<{
        progress: { completedCriteria: string[]; completionEvidence?: string };
      }>;
    };
    expect(validateFeatureList(featureList)).toBe(21);

    const incomplete = structuredClone(featureList);
    incomplete.features[0]?.progress.completedCriteria.pop();
    expect(() => validateFeatureList(incomplete)).toThrow(/record every acceptance criterion exactly/);

    const unevidenced = structuredClone(featureList);
    if (unevidenced.features[0] !== undefined) {
      delete unevidenced.features[0].progress.completionEvidence;
    }
    expect(() => validateFeatureList(unevidenced)).toThrow(/must record completion evidence/);
  });
});

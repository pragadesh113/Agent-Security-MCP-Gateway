import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const repositoryRoot = path.resolve(import.meta.dirname, "..");
const allowedStatuses = new Set(["planned", "in_progress", "blocked", "complete"]);

export function validateFeatureList(featureList) {
  const ids = new Set();

  if (featureList.currentPhase !== "phase-2-mcp-gateway") {
    throw new Error("docs/featurelist.json must identify Phase 2 as the current phase");
  }

  for (const feature of featureList.features) {
    if (ids.has(feature.id)) {
      throw new Error(`Duplicate feature ID: ${feature.id}`);
    }
    ids.add(feature.id);
    if (!allowedStatuses.has(feature.status)) {
      throw new Error(`Invalid status for ${feature.id}: ${feature.status}`);
    }
    if (!Array.isArray(feature.acceptanceCriteria) || feature.acceptanceCriteria.length === 0) {
      throw new Error(`${feature.id} must define at least one acceptance criterion`);
    }
    if (feature.status === "complete") {
      if (!feature.progress || !Array.isArray(feature.progress.completedCriteria)) {
        throw new Error(`Complete feature ${feature.id} must record completed criteria`);
      }
      if (typeof feature.progress.completionEvidence !== "string" || feature.progress.completionEvidence.trim() === "") {
        throw new Error(`Complete feature ${feature.id} must record completion evidence`);
      }
      const expected = new Set(feature.acceptanceCriteria);
      const completed = new Set(feature.progress.completedCriteria);
      if (completed.size !== feature.progress.completedCriteria.length) {
        throw new Error(`Complete feature ${feature.id} contains duplicate completed criteria`);
      }
      if (completed.size !== expected.size || [...expected].some((criterion) => !completed.has(criterion))) {
        throw new Error(`Complete feature ${feature.id} must record every acceptance criterion exactly`);
      }
      if (feature.progress.coverage !== "UNPROTECTED" || feature.progress.protectedForwardingEnabled !== false) {
        throw new Error(`Complete feature ${feature.id} must preserve the current UNPROTECTED non-forwarding posture`);
      }
    }
  }

  for (const feature of featureList.features) {
    for (const dependency of feature.dependencies) {
      if (!ids.has(dependency)) {
        throw new Error(`Unknown dependency ${dependency} on ${feature.id}`);
      }
    }
  }

  return featureList.features.length;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const featureList = JSON.parse(
    await readFile(path.join(repositoryRoot, "docs", "featurelist.json"), "utf8")
  );
  const featureCount = validateFeatureList(featureList);
  console.log(`Validated ${featureCount} feature records for Phase 2.`);
}

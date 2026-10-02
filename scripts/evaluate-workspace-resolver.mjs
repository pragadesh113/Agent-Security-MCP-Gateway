import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { performance } from "node:perf_hooks";

import { WorkspaceFileResolverV1 } from "../dist/src/action-normalizer/workspace-file-resolver-v1.js";
import { computeCanonicalDigestV1 } from "../dist/src/action-normalizer/canonical-action-v1.js";
import { evaluateResolverCorpusV1, resolverCorpusV1Schema } from "../dist/src/evaluation/resolver-corpus-v1.js";

const repository = path.resolve(import.meta.dirname, "..");
const corpusPath = "research/resolver/corpus-v1.json";
const corpus = resolverCorpusV1Schema.parse(JSON.parse(await readFile(path.join(repository, corpusPath), "utf8")));
const repetitions = 3;
const workspaceId = "resolver-development-fixture-v1";
const temporaryParent = path.resolve(os.tmpdir());
const temporaryRoot = await mkdtemp(path.join(temporaryParent, "agent-security-resolver-eval-"));
const confinedPath = (relativePath) => {
  const candidate = path.resolve(temporaryRoot, relativePath);
  const relative = path.relative(temporaryRoot, candidate);
  if (relative === "" || relative.startsWith(`..${path.sep}`) || relative === ".." || path.isAbsolute(relative)) {
    throw new Error("Fixture path escaped its disposable root");
  }
  return candidate;
};

try {
  for (const file of corpus.fixture.files) {
    const target = confinedPath(file.path);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, file.content, { flag: "wx" });
  }
  const referenceResourceIds = Object.create(null);
  for (const file of corpus.fixture.files) {
    // Independent OS observation of the labelled fixture, not a resolver prediction.
    const observed = await stat(confinedPath(file.path), { bigint: true });
    if (!observed.isFile() || observed.nlink !== 1n || observed.ino === 0n) throw new Error("Fixture identity is not a unique regular file");
    referenceResourceIds[file.path] = `file:${createHash("sha256")
      .update(JSON.stringify([workspaceId, observed.dev.toString(), observed.ino.toString()])).digest("hex")}`;
  }
  const resolver = new WorkspaceFileResolverV1({ rootDirectory: temporaryRoot, workspaceId, aliases: corpus.fixture.aliases });
  const trials = [];
  for (let repetition = 0; repetition < repetitions; repetition += 1) {
    for (const item of corpus.cases) {
      const start = performance.now();
      const resolution = resolver.resolve(item.input);
      trials.push({ caseId: item.caseId, repetition, resolution, elapsedMs: performance.now() - start });
    }
  }
  const evaluation = evaluateResolverCorpusV1({ corpus, repetitions, referenceResourceIds, trials });
  // Resolution is read-only even when the request describes a write or deletion.
  for (const file of corpus.fixture.files) {
    if (await readFile(confinedPath(file.path), "utf8") !== file.content) throw new Error("Resolver changed fixture content");
  }
  const sourcePaths = [
    corpusPath, "research/resolver/README.md", "package-lock.json", "tsconfig.json",
    "scripts/evaluate-workspace-resolver.mjs", "src/evaluation/resolver-corpus-v1.ts",
    "src/action-normalizer/workspace-file-resolver-v1.ts",
    "src/action-normalizer/canonical-action-v1.ts", "src/contracts/boundary-v1.ts"
  ];
  const sourceDigests = {};
  for (const sourcePath of sourcePaths) sourceDigests[sourcePath] = createHash("sha256").update(await readFile(path.join(repository, sourcePath))).digest("hex");
  const sourceRevision = execFileSync("git", ["rev-parse", "HEAD"], { cwd: repository, encoding: "utf8" }).trim();
  const sourceHasUncommittedChanges = execFileSync("git", ["status", "--porcelain"], { cwd: repository, encoding: "utf8" }).trim().length > 0;
  const report = {
    ...evaluation,
    execution: {
      observedAt: new Date().toISOString(), platform: process.platform, architecture: process.arch,
      nodeVersion: process.version, sourceRevision, sourceHasUncommittedChanges,
      sourceDigests, sourceDigest: computeCanonicalDigestV1(sourceDigests),
      parameters: { workspaceId, repetitions, iterationOrder: "CORPUS_ORDER", randomSeed: null },
      effectExecution: "NONE_RESOLUTION_ONLY", fixtureContentUnchanged: true,
      limitation: "Candidate label agreement; no held-out study, human label review, attack episodes, authorization comparison, or production assurance."
    }
  };
  report.artifactDigest = computeCanonicalDigestV1(report);
  const outputDirectory = path.join(repository, "artifacts");
  await mkdir(outputDirectory, { recursive: true });
  await writeFile(path.join(outputDirectory, "resolver-development-v1.json"), `${JSON.stringify(report, null, 2)}\n`);
  const failures = evaluation.failures.map((row) => `- ${row.caseId}, repetition ${row.repetition}: expected ${row.expectedStatus}/${row.expectedEffect}; observed ${row.observedStatus}/${row.observedEffect} (${row.reason ?? "resolved"})`);
  const summary = [
    "# Resolver development observations", "",
    `Observed: ${report.execution.observedAt}. Evidence: CANDIDATE_LABEL_DEVELOPMENT_ONLY.`, "",
    `- ${evaluation.cases} cases, ${evaluation.families} families, ${evaluation.repetitions} repetitions, ${evaluation.trials} trials.`,
    `- Candidate agreement: ${evaluation.metrics.candidateAgreement.count}/${evaluation.metrics.candidateAgreement.total}.`,
    `- Resource agreement among candidate-supported cases: ${evaluation.metrics.resourceAgreement.count}/${evaluation.metrics.resourceAgreement.total}.`,
    `- Effect agreement among candidate-supported cases: ${evaluation.metrics.effectAgreement.count}/${evaluation.metrics.effectAgreement.total}.`,
    `- Unexpected resolutions: ${evaluation.metrics.unexpectedResolution.count}/${evaluation.metrics.unexpectedResolution.total}.`,
    `- Unresolved: ${evaluation.metrics.unresolved.count}/${evaluation.metrics.unresolved.total}.`,
    `- Equivalence consistency: ${evaluation.metrics.equivalenceConsistency.count}/${evaluation.metrics.equivalenceConsistency.total} groups.`,
    `- Resolver-only warm-process latency: p50 ${evaluation.latencyMs.p50.toFixed(3)} ms; p95 ${evaluation.latencyMs.p95.toFixed(3)} ms.`,
    "", "## Failure records", "", ...(failures.length ? failures : ["No disagreement with these candidate labels was observed."]),
    "", "## Limits", "",
    "These are development cases exposed to implementers. Repetitions are not independent tasks. Labels lack independent human review. Requests were resolved without executing effects. This is not an estimate of attack prevention, false denial, task completion, or gateway overhead. Future held-out evaluation requires new untouched families. Coverage remains UNPROTECTED and protected forwarding disabled.",
    "", `Artifact digest: ${report.artifactDigest}`, ""
  ];
  await writeFile(path.join(outputDirectory, "resolver-development-v1.md"), summary.join("\n"));
  console.log(`Resolver development: ${evaluation.metrics.candidateAgreement.count}/${evaluation.trials} candidate agreements; ${evaluation.metrics.unresolved.count} unresolved; ${evaluation.failures.length} disagreements.`);
  console.log("Evidence: artifacts/resolver-development-v1.json and artifacts/resolver-development-v1.md (development-only, UNPROTECTED).");
  if (evaluation.failures.length > 0) process.exitCode = 1;
} finally {
  const relative = path.relative(temporaryParent, temporaryRoot);
  if (relative === "" || path.isAbsolute(relative) || relative.startsWith("..") || relative.includes(path.sep) || !relative.startsWith("agent-security-resolver-eval-")) {
    throw new Error("Refusing unsafe disposable fixture cleanup");
  }
  await rm(temporaryRoot, { recursive: true, force: true });
}

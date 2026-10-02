import { z } from "zod";

import { computeCanonicalDigestV1 } from "../action-normalizer/canonical-action-v1.js";
import { workspaceFileResolutionV1Schema } from "../action-normalizer/workspace-file-resolver-v1.js";
import { boundedProtocolJsonObjectV1Schema } from "../contracts/boundary-v1.js";

const identifier = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}$/u);
const digest = z.string().regex(/^[a-f0-9]{64}$/u);
const fixturePath = z.string().min(1).max(256).refine((value) => value.split("/").every((part) =>
  /^[A-Za-z0-9_-][A-Za-z0-9._ -]*$/u.test(part) && !/[. ]$/u.test(part) &&
  !/^(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/iu.test(part)), "Unsafe fixture path");
const expected = z.discriminatedUnion("status", [
  z.object({ status: z.literal("RESOLVED"), effect: z.enum(["READ", "WRITE", "DELETE"]), path: fixturePath }).strict(),
  z.object({ status: z.literal("UNRESOLVED"), effect: z.literal("UNKNOWN"), path: z.null() }).strict()
]);

export const resolverCorpusCaseV1Schema = z.object({
  caseId: identifier,
  familyId: identifier,
  equivalenceGroup: identifier.nullable(),
  intent: z.enum(["BENIGN", "ADVERSARIAL"]),
  input: z.object({
    schemaVersion: z.literal("1.0.0"),
    tool: z.string().min(1).max(128),
    arguments: boundedProtocolJsonObjectV1Schema
  }).strict(),
  expected,
  rationale: z.string().min(1).max(2_048)
}).strict();

/** Development labels cannot be promoted to reviewed or held-out evidence by a flag. */
export const resolverCorpusV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  corpusId: identifier,
  labelStatus: z.literal("CANDIDATE_UNREVIEWED"),
  partition: z.literal("DEVELOPMENT"),
  fixture: z.object({
    files: z.array(z.object({ path: fixturePath, content: z.string().max(65_536) }).strict()).min(1).max(256),
    aliases: z.record(identifier, fixturePath).refine((value) => Object.keys(value).length <= 256)
  }).strict(),
  cases: z.array(resolverCorpusCaseV1Schema).min(1).max(1_000)
}).strict().superRefine((corpus, context) => {
  const issue = (message: string): void => { context.addIssue({ code: "custom", message }); };
  const filePaths = new Set(corpus.fixture.files.map((file) => file.path));
  const folded = corpus.fixture.files.map((file) => file.path.toLowerCase());
  if (new Set(folded).size !== folded.length) issue("Duplicate or case-colliding fixture files");
  if (folded.some((file) => folded.some((other) => other.startsWith(`${file}/`)))) issue("Fixture file/directory collision");
  if (corpus.fixture.files.reduce((sum, file) => sum + Buffer.byteLength(file.content), 0) > 1_048_576) issue("Fixture content exceeds one MiB");
  for (const [alias, target] of Object.entries(corpus.fixture.aliases)) {
    if (["__proto__", "prototype", "constructor"].includes(alias) || !filePaths.has(target)) issue("Invalid fixture alias");
  }
  const ids = new Set<string>();
  const inputs = new Set<string>();
  const groups = new Map<string, string>();
  for (const item of corpus.cases) {
    if (ids.has(item.caseId)) issue("Duplicate case identifier");
    ids.add(item.caseId);
    const inputDigest = computeCanonicalDigestV1(item.input);
    if (inputs.has(inputDigest)) issue("Duplicate case input");
    inputs.add(inputDigest);
    if (item.expected.path !== null && !filePaths.has(item.expected.path)) issue("Expected target is not a fixture file");
    if (item.equivalenceGroup !== null) {
      const groupBinding = computeCanonicalDigestV1({ familyId: item.familyId, expected: item.expected });
      const previous = groups.get(item.equivalenceGroup);
      if (item.expected.status !== "RESOLVED" || (previous !== undefined && previous !== groupBinding)) {
        issue("Equivalent cases must share one family and expected semantics");
      }
      groups.set(item.equivalenceGroup, groupBinding);
    }
  }
});
export type ResolverCorpusV1 = z.infer<typeof resolverCorpusV1Schema>;
export type ResolverCorpusCaseV1 = z.infer<typeof resolverCorpusCaseV1Schema>;

export const resolverTrialV1Schema = z.object({
  caseId: identifier,
  repetition: z.number().int().min(0).max(99),
  resolution: workspaceFileResolutionV1Schema,
  elapsedMs: z.number().finite().nonnegative().max(3_600_000)
}).strict();
export type ResolverTrialV1 = z.infer<typeof resolverTrialV1Schema>;

export interface ResolverEvaluationV1Input {
  readonly corpus: unknown;
  readonly trials: readonly unknown[];
  readonly repetitions: number;
  /** IDs are independently observed from fixture dev/ino, never inferred from predictions. */
  readonly referenceResourceIds: Readonly<Record<string, string>>;
}

function metric(count: number, total: number) {
  return { count, total, rate: total === 0 ? null : count / total };
}

/** Pure accounting. It neither executes operations nor estimates attack prevention. */
export function evaluateResolverCorpusV1(input: ResolverEvaluationV1Input) {
  const corpus = resolverCorpusV1Schema.parse(input.corpus);
  const repetitions = z.number().int().min(2).max(100).parse(input.repetitions);
  const trials = z.array(resolverTrialV1Schema).max(100_000).parse(input.trials);
  const references = z.record(fixturePath, z.string().regex(/^file:[a-f0-9]{64}$/u)).parse(input.referenceResourceIds);
  const requiredPaths = corpus.fixture.files.map((file) => file.path);
  if (Object.keys(references).length !== requiredPaths.length || requiredPaths.some((path) => references[path] === undefined) ||
    new Set(Object.values(references)).size !== requiredPaths.length) {
    throw new Error("Resolver evaluation requires exact independent fixture identities");
  }
  const byId = new Map(corpus.cases.map((item) => [item.caseId, item]));
  const seen = new Set<string>();
  const rows = trials.map((trial) => {
    const item = byId.get(trial.caseId);
    const key = `${trial.caseId}:${trial.repetition}`;
    if (item === undefined || trial.repetition >= repetitions || seen.has(key)) throw new Error("Unknown, duplicate, or out-of-range resolver trial");
    seen.add(key);
    const statusMatches = trial.resolution.status === item.expected.status;
    const bothResolved = trial.resolution.status === "RESOLVED" && item.expected.status === "RESOLVED";
    const resourceMatches = bothResolved && trial.resolution.resource?.resourceId === references[item.expected.path ?? ""];
    const effectMatches = bothResolved && trial.resolution.effect === item.expected.effect;
    const candidateMatches = statusMatches && (item.expected.status === "UNRESOLVED" || (resourceMatches && effectMatches));
    return {
      caseId: item.caseId, familyId: item.familyId, equivalenceGroup: item.equivalenceGroup,
      intent: item.intent, repetition: trial.repetition,
      expectedStatus: item.expected.status, expectedEffect: item.expected.effect,
      observedStatus: trial.resolution.status, observedEffect: trial.resolution.effect,
      reason: trial.resolution.reason,
      statusMatches, resourceMatches, effectMatches, candidateMatches,
      unexpectedResolution: trial.resolution.status === "RESOLVED" && !candidateMatches,
      elapsedMs: trial.elapsedMs,
      resolutionDigest: computeCanonicalDigestV1(trial.resolution)
    };
  }).sort((a, b) => a.caseId.localeCompare(b.caseId) || a.repetition - b.repetition);
  if (rows.length !== corpus.cases.length * repetitions) throw new Error("Resolver evaluation is missing trials");

  const supported = rows.filter((row) => row.expectedStatus === "RESOLVED");
  const groups = new Map<string, Set<string>>();
  for (const trial of trials) {
    const group = byId.get(trial.caseId)?.equivalenceGroup;
    if (group === null || group === undefined) continue;
    const observations = groups.get(group) ?? new Set<string>();
    observations.add(computeCanonicalDigestV1({
      status: trial.resolution.status, effect: trial.resolution.effect,
      resourceId: trial.resolution.resource?.resourceId ?? null
    }));
    groups.set(group, observations);
  }
  const latencies = rows.map((row) => row.elapsedMs).sort((a, b) => a - b);
  const percentile = (fraction: number): number => latencies[Math.max(0, Math.ceil(fraction * latencies.length) - 1)] ?? 0;
  const report = {
    schemaVersion: "1.0.0" as const,
    evidenceClass: "CANDIDATE_LABEL_DEVELOPMENT_ONLY" as const,
    coverage: "UNPROTECTED" as const,
    protectedForwardingEnabled: false as const,
    independentlyReviewed: false as const,
    corpusId: corpus.corpusId,
    corpusDigest: computeCanonicalDigestV1(corpus),
    fixtureDigest: computeCanonicalDigestV1(corpus.fixture),
    referenceIdentitiesDigest: computeCanonicalDigestV1(references),
    repetitions, cases: corpus.cases.length,
    families: new Set(corpus.cases.map((item) => item.familyId)).size,
    trials: rows.length,
    metrics: {
      candidateAgreement: metric(rows.filter((row) => row.candidateMatches).length, rows.length),
      resourceAgreement: metric(supported.filter((row) => row.resourceMatches).length, supported.length),
      effectAgreement: metric(supported.filter((row) => row.effectMatches).length, supported.length),
      unexpectedResolution: metric(rows.filter((row) => row.unexpectedResolution).length, rows.length),
      unresolved: metric(rows.filter((row) => row.observedStatus === "UNRESOLVED").length, rows.length),
      unresolvedWithinCandidateSupported: metric(supported.filter((row) => row.observedStatus === "UNRESOLVED").length, supported.length),
      equivalenceConsistency: metric([...groups.values()].filter((values) => values.size === 1).length, groups.size)
    },
    latencyMs: { measurement: "RESOLVER_ONLY_WARM_PROCESS" as const, mean: latencies.reduce((sum, value) => sum + value, 0) / latencies.length, p50: percentile(0.5), p95: percentile(0.95) },
    perFamily: [...new Set(rows.map((row) => row.familyId))].sort().map((familyId) => {
      const familyRows = rows.filter((row) => row.familyId === familyId);
      return { familyId, agreement: metric(familyRows.filter((row) => row.candidateMatches).length, familyRows.length) };
    }),
    failures: rows.filter((row) => !row.candidateMatches),
    rows
  };
  return { ...report, evidenceDigest: digest.parse(computeCanonicalDigestV1(report)) };
}

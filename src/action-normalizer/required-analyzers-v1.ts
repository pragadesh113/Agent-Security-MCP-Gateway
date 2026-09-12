import { z } from "zod";

export const requiredAnalyzerCategoriesV1 = [
  "FILESYSTEM", "SHELL", "GIT", "PACKAGE", "NETWORK", "DATABASE", "CLOUD",
  "BROWSER", "PROCESS", "DEPLOYMENT", "SCHEMA"
] as const;

export const requiredAnalyzerCategoryV1Schema = z.enum(requiredAnalyzerCategoriesV1);
export type RequiredAnalyzerCategoryV1 = z.infer<typeof requiredAnalyzerCategoryV1Schema>;

const boundedName = z.string().trim().min(1).max(128);

export const requiredAnalyzerRequestV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  category: requiredAnalyzerCategoryV1Schema,
  operation: boundedName,
  syntax: boundedName,
  syntaxVersion: boundedName,
  input: z.unknown()
}).strict();
export type RequiredAnalyzerRequestV1 = z.infer<typeof requiredAnalyzerRequestV1Schema>;

export const requiredAnalyzerFindingV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  analyzerId: boundedName,
  analyzerVersion: boundedName,
  category: requiredAnalyzerCategoryV1Schema,
  operation: boundedName,
  syntax: boundedName,
  syntaxVersion: boundedName,
  status: z.literal("RESOLVED"),
  complete: z.literal(true),
  ambiguous: z.literal(false),
  effect: z.enum(["READ", "WRITE", "EXECUTE", "DELETE", "DISCLOSE", "ADMINISTER"]),
  resources: z.array(z.object({
    resourceId: boundedName,
    canonicalReference: z.string().trim().min(1).max(4_096)
  }).strict()).min(1).max(64),
  evidence: z.array(boundedName).min(1).max(64)
}).strict();
export type RequiredAnalyzerFindingV1 = z.infer<typeof requiredAnalyzerFindingV1Schema>;

export const quarantinedAnalyzerFindingV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  category: requiredAnalyzerCategoryV1Schema,
  operation: z.string().max(128),
  syntax: z.string().max(128),
  syntaxVersion: z.string().max(128),
  status: z.literal("QUARANTINED"),
  complete: z.literal(false),
  ambiguous: z.literal(true),
  effect: z.literal("UNKNOWN"),
  resources: z.tuple([z.object({
    resourceId: z.literal("unresolved"),
    canonicalReference: z.literal("unresolved")
  }).strict()]),
  reason: z.enum([
    "MISSING_ANALYZER", "UNKNOWN_OPERATION", "UNKNOWN_SYNTAX", "UNKNOWN_VERSION",
    "ANALYZER_FAILURE", "INVALID_RESULT", "PARTIAL_RESULT"
  ])
}).strict();
export type QuarantinedAnalyzerFindingV1 = z.infer<typeof quarantinedAnalyzerFindingV1Schema>;
export type RequiredAnalyzerOutcomeV1 = RequiredAnalyzerFindingV1 | QuarantinedAnalyzerFindingV1;

export interface RequiredAnalyzerV1 {
  readonly category: RequiredAnalyzerCategoryV1;
  readonly supportedOperations: readonly string[];
  readonly supportedSyntaxes: Readonly<Record<string, readonly string[]>>;
  analyze(request: RequiredAnalyzerRequestV1): unknown;
}

export type RequiredAnalyzerSetV1 = Partial<Record<RequiredAnalyzerCategoryV1, RequiredAnalyzerV1>>;

export class RequiredAnalyzerConfigurationErrorV1 extends Error {
  public constructor() {
    super("Required analyzer configuration is invalid");
    this.name = "RequiredAnalyzerConfigurationErrorV1";
  }
}

function validatedAnalyzer(
  configuredCategory: RequiredAnalyzerCategoryV1,
  analyzer: RequiredAnalyzerV1
): RequiredAnalyzerV1 {
  if (analyzer.category !== configuredCategory || typeof analyzer.analyze !== "function") {
    throw new RequiredAnalyzerConfigurationErrorV1();
  }
  const operations = [...analyzer.supportedOperations];
  if (operations.length === 0 ||
    operations.some((item) => !boundedName.safeParse(item).success) ||
    new Set(operations).size !== operations.length) {
    throw new RequiredAnalyzerConfigurationErrorV1();
  }
  const syntaxes: Record<string, readonly string[]> = {};
  const syntaxEntries = Object.entries(analyzer.supportedSyntaxes);
  if (syntaxEntries.length === 0) throw new RequiredAnalyzerConfigurationErrorV1();
  for (const [syntax, configuredVersions] of syntaxEntries) {
    const versions = [...configuredVersions];
    if (!boundedName.safeParse(syntax).success || versions.length === 0 ||
      versions.some((version) => !boundedName.safeParse(version).success) ||
      new Set(versions).size !== versions.length) {
      throw new RequiredAnalyzerConfigurationErrorV1();
    }
    syntaxes[syntax] = Object.freeze(versions);
  }
  return Object.freeze({
    category: analyzer.category,
    supportedOperations: Object.freeze(operations),
    supportedSyntaxes: Object.freeze(syntaxes),
    analyze: analyzer.analyze.bind(analyzer)
  });
}

function quarantine(
  request: Pick<RequiredAnalyzerRequestV1, "category" | "operation" | "syntax" | "syntaxVersion">,
  reason: QuarantinedAnalyzerFindingV1["reason"]
): QuarantinedAnalyzerFindingV1 {
  return {
    schemaVersion: "1.0.0", category: request.category,
    operation: request.operation, syntax: request.syntax, syntaxVersion: request.syntaxVersion,
    status: "QUARANTINED", complete: false, ambiguous: true, effect: "UNKNOWN",
    resources: [{ resourceId: "unresolved", canonicalReference: "unresolved" }], reason
  };
}

export class RequiredAnalyzerRegistryV1 {
  readonly #analyzers: ReadonlyMap<RequiredAnalyzerCategoryV1, RequiredAnalyzerV1>;

  public constructor(analyzers: RequiredAnalyzerSetV1) {
    const validated = new Map<RequiredAnalyzerCategoryV1, RequiredAnalyzerV1>();
    for (const category of requiredAnalyzerCategoriesV1) {
      const analyzer = analyzers[category];
      if (analyzer !== undefined) validated.set(category, validatedAnalyzer(category, analyzer));
    }
    this.#analyzers = validated;
  }

  public async analyze(requestInput: unknown): Promise<RequiredAnalyzerOutcomeV1> {
    const parsed = requiredAnalyzerRequestV1Schema.safeParse(requestInput);
    if (!parsed.success) {
      const candidate = requestInput as Partial<RequiredAnalyzerRequestV1> | null;
      const category = requiredAnalyzerCategoryV1Schema.safeParse(candidate?.category);
      return quarantine({
        category: category.success ? category.data : "SCHEMA",
        operation: typeof candidate?.operation === "string" ? candidate.operation.slice(0, 128) : "",
        syntax: typeof candidate?.syntax === "string" ? candidate.syntax.slice(0, 128) : "",
        syntaxVersion: typeof candidate?.syntaxVersion === "string" ? candidate.syntaxVersion.slice(0, 128) : ""
      }, "INVALID_RESULT");
    }
    const request = parsed.data;
    const analyzer = this.#analyzers.get(request.category);
    if (analyzer === undefined || analyzer.category !== request.category) {
      return quarantine(request, "MISSING_ANALYZER");
    }
    if (!analyzer.supportedOperations.includes(request.operation)) {
      return quarantine(request, "UNKNOWN_OPERATION");
    }
    const versions = analyzer.supportedSyntaxes[request.syntax];
    if (versions === undefined) return quarantine(request, "UNKNOWN_SYNTAX");
    if (!versions.includes(request.syntaxVersion)) return quarantine(request, "UNKNOWN_VERSION");
    let candidate: unknown;
    try {
      candidate = await analyzer.analyze(request);
    } catch {
      return quarantine(request, "ANALYZER_FAILURE");
    }
    const finding = requiredAnalyzerFindingV1Schema.safeParse(candidate);
    if (!finding.success) {
      const partial = candidate !== null && typeof candidate === "object" &&
        ((candidate as { complete?: unknown }).complete === false ||
          (candidate as { status?: unknown }).status === "PARTIAL");
      return quarantine(request, partial ? "PARTIAL_RESULT" : "INVALID_RESULT");
    }
    if (finding.data.category !== request.category || finding.data.operation !== request.operation ||
      finding.data.syntax !== request.syntax || finding.data.syntaxVersion !== request.syntaxVersion) {
      return quarantine(request, "INVALID_RESULT");
    }
    return finding.data;
  }
}

export type CompleteRequiredAnalyzerSetV1 = Record<RequiredAnalyzerCategoryV1, RequiredAnalyzerV1>;

/** Production activation gate: every protected category must have its own validated analyzer. */
export function createCompleteRequiredAnalyzerRegistryV1(
  analyzers: RequiredAnalyzerSetV1
): RequiredAnalyzerRegistryV1 {
  if (requiredAnalyzerCategoriesV1.some((category) => analyzers[category] === undefined)) {
    throw new RequiredAnalyzerConfigurationErrorV1();
  }
  return new RequiredAnalyzerRegistryV1(analyzers);
}

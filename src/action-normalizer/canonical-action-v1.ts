import { createHash, randomUUID } from "node:crypto";

import { z } from "zod";

import { toolCallRequestV1Schema, type ToolCallRequestV1 } from "../contracts/boundary-v1.js";
import { canonicalActionV1Schema, type CanonicalActionV1 } from "../contracts/trajectory-v1.js";
import {
  capabilityIdentifierV1Schema,
  downstreamServerRouteBindingV1Schema,
  identifierV1Schema,
  type DownstreamServerRouteBindingV1
} from "../contracts/v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema,
  type AuthenticatedSessionIdentityBindingV1
} from "../identity/client-authentication-v1.js";

const resourceClassV1Schema = z.enum([
  "FILESYSTEM", "SHELL", "GIT", "PACKAGE", "NETWORK", "DATABASE", "CLOUD",
  "BROWSER", "PROCESS", "DEPLOYMENT", "UNKNOWN"
]);
const classificationV1Schema = z.enum([
  "PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "CREDENTIAL", "UNKNOWN"
]);
const effectV1Schema = z.enum([
  "READ", "WRITE", "EXECUTE", "DELETE", "DISCLOSE", "ADMINISTER", "UNKNOWN"
]);
const environmentV1Schema = z.enum([
  "DEVELOPMENT", "TEST", "STAGING", "PRODUCTION", "UNKNOWN"
]);

export const canonicalResourceCandidateV1Schema = z.object({
  resourceId: identifierV1Schema,
  resourceClass: resourceClassV1Schema,
  reference: z.string().trim().min(1).max(4_096),
  referencePlatform: z.enum(["WINDOWS", "POSIX", "URI", "OPAQUE"]),
  classification: classificationV1Schema
}).strict();

export const canonicalActionAnalysisV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  parserId: identifierV1Schema,
  parserVersion: z.string().trim().min(1).max(64),
  status: z.enum(["FULL", "PARTIAL", "FAILED", "UNSUPPORTED"]),
  resources: z.array(canonicalResourceCandidateV1Schema).min(1).max(64),
  effect: effectV1Schema,
  environment: environmentV1Schema,
  dataFlow: z.object({
    direction: z.enum(["NONE", "INGRESS", "EGRESS", "BIDIRECTIONAL", "UNKNOWN"]),
    classifications: z.array(classificationV1Schema).min(1).max(16),
    externalDestination: z.boolean(),
    destinationId: identifierV1Schema.nullable()
  }).strict(),
  reversibility: z.enum([
    "NOT_APPLICABLE", "VERIFIED_COMPENSATING_ACTION", "TESTED_SNAPSHOT",
    "PARTIALLY_REVERSIBLE", "IRREVERSIBLE", "UNKNOWN"
  ]),
  influences: z.array(z.enum([
    "USER_INPUT", "TOOL_DESCRIPTION", "TOOL_RESULT", "RESOURCE_CONTENT",
    "MODEL_GENERATED", "UNKNOWN"
  ])).max(16)
}).strict().superRefine((analysis, context) => {
  if (analysis.environment === "UNKNOWN" && analysis.status === "FULL") {
    context.addIssue({ code: "custom", path: ["status"], message: "Unknown environments cannot be fully parsed" });
  }
  if ((analysis.effect === "UNKNOWN" || analysis.resources.some((item) => item.resourceClass === "UNKNOWN")) && analysis.status === "FULL") {
    context.addIssue({ code: "custom", path: ["status"], message: "Unknown effects or resources cannot be fully parsed" });
  }
  if (analysis.dataFlow.externalDestination !== (analysis.dataFlow.destinationId !== null)) {
    context.addIssue({ code: "custom", path: ["dataFlow", "destinationId"], message: "External destinations require one destination identifier" });
  }
});

export type CanonicalActionAnalysisV1 = z.infer<typeof canonicalActionAnalysisV1Schema>;
export type CanonicalResourceCandidateV1 = z.infer<typeof canonicalResourceCandidateV1Schema>;
export type CanonicalActionResolverV1 = (context: {
  readonly arguments: ToolCallRequestV1["arguments"];
  readonly binding: DownstreamServerRouteBindingV1;
}) => unknown;

export class CanonicalizationDeniedV1 extends Error {
  public constructor() {
    super("Canonical action normalization denied");
    this.name = "CanonicalizationDeniedV1";
  }
}

function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(",")}]`;
  }
  return `{${Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`).join(",")}}`;
}

export function computeCanonicalDigestV1(value: unknown): string {
  return createHash("sha256").update(stableJson(value), "utf8").digest("hex");
}

export function computeCanonicalJsonByteLengthV1(value: unknown): number {
  return Buffer.byteLength(stableJson(value), "utf8");
}

function decodePercent(value: string): string {
  let decoded = value;
  for (let attempt = 0; attempt < 16; attempt += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) return next;
      decoded = next;
    } catch {
      throw new CanonicalizationDeniedV1();
    }
  }
  throw new CanonicalizationDeniedV1();
}

function normalizePath(value: string, windows: boolean): string {
  let path = decodePercent(value.normalize("NFC")).replaceAll("\\", "/");
  for (let index = 0; index < path.length; index += 1) {
    const codeUnit = path.charCodeAt(index);
    if (codeUnit <= 31 || codeUnit === 127) throw new CanonicalizationDeniedV1();
  }
  if (path.toLowerCase().startsWith("file://")) {
    try {
      path = decodePercent(new URL(path).pathname);
    } catch {
      // A trusted resolver may still classify an unusual local path; normalize it below.
    }
  }
  const unc = path.startsWith("//");
  const driveMatch = /^\/?([A-Za-z]):(?:\/|$)/u.exec(path);
  const drive = driveMatch?.[1];
  if (driveMatch !== null) path = path.slice(driveMatch[0].length);
  const segments: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      if (segments.length > 0) segments.pop();
      continue;
    }
    segments.push(segment);
  }
  const root = drive !== undefined ? `${drive.toUpperCase()}:/` : unc ? "//" : path.startsWith("/") ? "/" : "";
  const normalized = `${root}${segments.join("/")}`;
  return windows ? normalized.toLocaleLowerCase("en-US") : normalized;
}

export function normalizeCanonicalReferenceV1(candidateInput: CanonicalResourceCandidateV1): string {
  const candidate = canonicalResourceCandidateV1Schema.parse(candidateInput);
  if (candidate.referencePlatform === "WINDOWS") return normalizePath(candidate.reference, true);
  if (candidate.referencePlatform === "POSIX") return normalizePath(candidate.reference, false);
  if (candidate.referencePlatform === "URI") {
    const parsed = new URL(decodePercent(candidate.reference.normalize("NFC")));
    if (parsed.username !== "" || parsed.password !== "") throw new CanonicalizationDeniedV1();
    parsed.hostname = parsed.hostname.toLowerCase();
    parsed.pathname = normalizePath(parsed.pathname, false);
    if ((parsed.protocol === "https:" && parsed.port === "443") || (parsed.protocol === "http:" && parsed.port === "80")) parsed.port = "";
    parsed.hash = "";
    parsed.searchParams.sort();
    return parsed.toString();
  }
  return decodePercent(candidate.reference.normalize("NFC")).trim();
}

function argumentKeyIdentifier(key: string): string {
  const lowered = key.normalize("NFC").toLowerCase();
  const parsed = capabilityIdentifierV1Schema.safeParse(lowered);
  return parsed.success ? parsed.data : `argument.${computeCanonicalDigestV1(key).slice(0, 24)}`;
}

function unresolvedAnalysis(binding: DownstreamServerRouteBindingV1): CanonicalActionAnalysisV1 {
  return canonicalActionAnalysisV1Schema.parse({
    schemaVersion: "1.0.0",
    parserId: binding.route.resourceMapping.resolverId,
    parserVersion: "unavailable",
    status: "UNSUPPORTED",
    resources: [{
      resourceId: `unresolved:${computeCanonicalDigestV1(binding.route.routeId).slice(0, 24)}`,
      resourceClass: "UNKNOWN",
      reference: `unresolved:${binding.route.routeId}`,
      referencePlatform: "OPAQUE",
      classification: "UNKNOWN"
    }],
    effect: "UNKNOWN",
    environment: "UNKNOWN",
    dataFlow: { direction: "UNKNOWN", classifications: ["UNKNOWN"], externalDestination: false, destinationId: null },
    reversibility: "UNKNOWN",
    influences: ["UNKNOWN"]
  });
}

export interface CanonicalActionNormalizerV1Options {
  readonly resolvers: ReadonlyMap<string, CanonicalActionResolverV1>;
  readonly clock?: () => Date;
  readonly actionIdFactory?: () => string;
}

export class CanonicalActionNormalizerV1 {
  readonly #options: CanonicalActionNormalizerV1Options;

  public constructor(options: CanonicalActionNormalizerV1Options) {
    this.#options = options;
  }

  public normalize(input: {
    readonly request: unknown;
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly binding: DownstreamServerRouteBindingV1;
    readonly ancestorActions?: readonly CanonicalActionV1[];
  }): CanonicalActionV1 {
    const request = toolCallRequestV1Schema.parse(input.request);
    const session = authenticatedSessionIdentityBindingV1Schema.parse(input.session);
    const binding = downstreamServerRouteBindingV1Schema.parse(input.binding);
    const ancestors = (input.ancestorActions ?? []).map((action) => canonicalActionV1Schema.parse(action));
    const routeMatches = request.route.serverId === binding.server.serverId &&
      request.route.routeId === binding.route.routeId && request.route.toolName === binding.route.toolName &&
      request.route.schemaDigest === binding.route.schemaIntegrity.registeredDigest &&
      request.route.credentialAudienceId === binding.route.credentialAudienceId &&
      request.route.policyScopeId === binding.route.policyScopeId;
    const chainMatches = ancestors.length === request.callChain.depth &&
      (ancestors.length === 0 ? request.callChain.parentRequestId === null :
        request.callChain.parentRequestId === ancestors.at(-1)?.requestId) &&
      ancestors.every((action) => action.sessionId === session.stateNamespace && action.callChain.callChainId === request.callChain.callChainId);
    if (!routeMatches || request.sessionId !== session.stateNamespace || !chainMatches ||
      computeCanonicalDigestV1(request.arguments) !== request.argumentsDigest ||
      computeCanonicalJsonByteLengthV1(request.arguments) !== request.payloadBytes) {
      throw new CanonicalizationDeniedV1();
    }

    const resolver = this.#options.resolvers.get(binding.route.resourceMapping.resolverId);
    let analysis: CanonicalActionAnalysisV1;
    try {
      analysis = resolver === undefined
        ? unresolvedAnalysis(binding)
        : canonicalActionAnalysisV1Schema.parse(resolver({ arguments: request.arguments, binding }));
    } catch {
      analysis = unresolvedAnalysis(binding);
    }
    if (analysis.status === "FULL" && (analysis.environment !== binding.route.environment ||
      analysis.resources.some((resource) => resource.resourceClass !== binding.route.resourceMapping.resourceClass))) {
      analysis = { ...unresolvedAnalysis(binding), parserId: analysis.parserId, parserVersion: analysis.parserVersion, status: "FAILED" };
    }

    const resources = analysis.resources.map((resource) => ({
      resourceId: resource.resourceId,
      resourceClass: resource.resourceClass,
      canonicalReference: normalizeCanonicalReferenceV1(resource),
      classification: resource.classification
    })).sort((left, right) => left.resourceId.localeCompare(right.resourceId));
    const dataFlow = { ...analysis.dataFlow, classifications: [...new Set(analysis.dataFlow.classifications)].sort() };
    const argumentKeys = [...new Set(Object.keys(request.arguments).map(argumentKeyIdentifier))].sort();
    const evidence = {
      parserId: analysis.parserId, parserVersion: analysis.parserVersion, status: analysis.status,
      resources, effect: analysis.effect, environment: analysis.environment, dataFlow,
      reversibility: analysis.reversibility, influences: [...new Set(analysis.influences)].sort()
    };
    const actionWithoutHash = {
      schemaVersion: "1.0.0" as const,
      requestId: request.requestId,
      actionId: identifierV1Schema.parse(this.#options.actionIdFactory?.() ?? randomUUID()),
      sessionId: session.stateNamespace,
      identity: {
        userId: session.identity.userId, agentId: session.identity.agentId,
        clientId: session.identity.clientId, hostId: session.identity.hostId
      },
      route: {
        serverId: binding.server.serverId, routeId: binding.route.routeId,
        toolName: binding.route.toolName, schemaDigest: binding.route.schemaIntegrity.registeredDigest,
        credentialAudienceId: binding.route.credentialAudienceId, policyScopeId: binding.route.policyScopeId
      },
      arguments: { digest: request.argumentsDigest, keys: argumentKeys, secretValuesRemoved: true as const },
      resources,
      resourcesDigest: computeCanonicalDigestV1(resources),
      effect: analysis.effect,
      environment: analysis.environment,
      dataFlow,
      dataFlowDigest: computeCanonicalDigestV1(dataFlow),
      parsingEvidence: {
        parserId: analysis.parserId, parserVersion: analysis.parserVersion,
        status: analysis.status, evidenceDigest: computeCanonicalDigestV1(evidence)
      },
      reversibility: analysis.reversibility,
      callChain: {
        callChainId: request.callChain.callChainId,
        parentActionId: ancestors.at(-1)?.actionId ?? null,
        ancestorActionIds: ancestors.map((action) => action.actionId),
        depth: request.callChain.depth,
        delegationDepth: request.callChain.delegationDepth
      },
      influences: [...new Set(analysis.influences)].sort(),
      createdAt: (this.#options.clock?.() ?? new Date()).toISOString()
    };
    return canonicalActionV1Schema.parse({
      ...actionWithoutHash,
      actionHash: computeCanonicalDigestV1(actionWithoutHash)
    });
  }
}

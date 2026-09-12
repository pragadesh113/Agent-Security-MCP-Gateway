import { z } from "zod";

import {
  capabilityIdentifierV1Schema,
  coverageStateV1Schema,
  downstreamServerV1Schema,
  gatewayClientV1Schema,
  gatewaySessionV1Schema,
  identifierV1Schema,
  sha256DigestV1Schema,
  toolRouteV1Schema,
  utcTimestampV1Schema
} from "./v1.js";
import {
  approvalV1Schema,
  canonicalActionV1Schema,
  downstreamProvenanceV1Schema,
  downstreamResultV1Schema,
  executionOutcomeV1Schema,
  policyDecisionV1Schema
} from "./trajectory-v1.js";

const MAX_JSON_DEPTH = 32;
const MAX_JSON_NODES = 4_096;
const MAX_JSON_STRING_CODE_UNITS = 1_048_576;
const forbiddenObjectKeys = new Set(["__proto__", "constructor", "prototype"]);

export const untrustedProtocolJsonShapeGuardV1Schema = z
  .unknown()
  .superRefine((value, context) => {
  const pending: Array<{ depth: number; value: unknown }> = [
    { depth: 0, value }
  ];
  let nodes = 0;
  let stringCodeUnits = 0;

  while (pending.length > 0) {
    const current = pending.pop();
    if (current === undefined) {
      break;
    }

    nodes += 1;
    if (nodes > MAX_JSON_NODES) {
      context.addIssue({ code: "custom", message: "JSON value exceeds the node limit" });
      return;
    }
    if (current.depth > MAX_JSON_DEPTH) {
      context.addIssue({ code: "custom", message: "JSON value exceeds the depth limit" });
      return;
    }

    if (typeof current.value === "string") {
      stringCodeUnits += current.value.length;
      if (stringCodeUnits > MAX_JSON_STRING_CODE_UNITS) {
        context.addIssue({
          code: "custom",
          message: "JSON strings exceed the aggregate length limit"
        });
        return;
      }
      continue;
    }

    if (Array.isArray(current.value)) {
      current.value.forEach((entry) => {
        pending.push({ depth: current.depth + 1, value: entry });
      });
      continue;
    }

    if (current.value !== null && typeof current.value === "object") {
      for (const [key, entry] of Object.entries(current.value)) {
        if (forbiddenObjectKeys.has(key)) {
          context.addIssue({
            code: "custom",
            message: `JSON object key ${key} is not accepted at a protocol boundary`
          });
          return;
        }
        stringCodeUnits += key.length;
        pending.push({ depth: current.depth + 1, value: entry });
      }
    }
  }
  });

export const boundedProtocolJsonV1Schema = untrustedProtocolJsonShapeGuardV1Schema.pipe(
  z.json()
);

export const boundedProtocolJsonObjectV1Schema = untrustedProtocolJsonShapeGuardV1Schema
  .pipe(z.record(z.string().min(1).max(256), boundedProtocolJsonV1Schema))
  .superRefine((value, context) => {
    const keys = Object.keys(value);
    if (keys.length > 256) {
      context.addIssue({ code: "custom", message: "JSON object has too many properties" });
    }
    if (keys.some((key) => forbiddenObjectKeys.has(key))) {
      context.addIssue({
        code: "custom",
        message: "JSON object contains a key that is not accepted at a protocol boundary"
      });
    }
  });

const safeDisplayTextV1Schema = z
  .string()
  .trim()
  .min(1)
  .max(2_048)
  .refine((value) => {
    for (let index = 0; index < value.length; index += 1) {
      const codeUnit = value.charCodeAt(index);
      if (codeUnit <= 31 || codeUnit === 127) {
        return false;
      }
    }
    return true;
  }, "Display text cannot contain control characters");

const environmentV1Schema = z.enum([
  "DEVELOPMENT",
  "TEST",
  "STAGING",
  "PRODUCTION",
  "UNKNOWN"
]);

const routeCallBindingV1Schema = z
  .object({
    serverId: identifierV1Schema,
    routeId: identifierV1Schema,
    toolName: capabilityIdentifierV1Schema,
    exposedName: capabilityIdentifierV1Schema,
    schemaDigest: sha256DigestV1Schema,
    credentialAudienceId: identifierV1Schema,
    policyScopeId: identifierV1Schema
  })
  .strict();

const discoveredToolV1Schema = z
  .object({
    route: routeCallBindingV1Schema,
    title: z.string().trim().min(1).max(256).nullable(),
    description: z.string().max(16_384).nullable(),
    inputSchema: boundedProtocolJsonObjectV1Schema,
    outputSchema: boundedProtocolJsonObjectV1Schema.nullable(),
    annotations: boundedProtocolJsonObjectV1Schema.nullable(),
    availability: z.enum(["AVAILABLE", "UNAVAILABLE", "QUARANTINED"]),
    contentTrust: z.literal("UNTRUSTED"),
    callTimeAuthorizationRequired: z.literal(true)
  })
  .strict();

export const discoveryResultV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    requestId: identifierV1Schema,
    sessionId: identifierV1Schema,
    policyScopeId: identifierV1Schema,
    environment: environmentV1Schema,
    tools: z.array(discoveredToolV1Schema).max(1_000),
    coverage: coverageStateV1Schema,
    generatedAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((discovery, context) => {
    const routeIds = new Set<string>();
    const exposedNames = new Set<string>();

    discovery.tools.forEach((tool, index) => {
      if (tool.route.policyScopeId !== discovery.policyScopeId) {
        context.addIssue({
          code: "custom",
          path: ["tools", index, "route", "policyScopeId"],
          message: "Discovered routes must remain inside the requested policy scope"
        });
      }
      if (routeIds.has(tool.route.routeId)) {
        context.addIssue({
          code: "custom",
          path: ["tools", index, "route", "routeId"],
          message: "Discovery route IDs must be unique"
        });
      }
      routeIds.add(tool.route.routeId);

      const exposedName = tool.route.exposedName.toLowerCase();
      if (exposedNames.has(exposedName)) {
        context.addIssue({
          code: "custom",
          path: ["tools", index, "route", "exposedName"],
          message: "Discovery cannot expose an ambiguous tool name"
        });
      }
      exposedNames.add(exposedName);
    });
  });

export const toolCallRequestV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    requestId: identifierV1Schema,
    protocolRequestId: z.union([
      z.string().min(1).max(128),
      z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
    ]),
    sessionId: identifierV1Schema,
    route: routeCallBindingV1Schema,
    arguments: boundedProtocolJsonObjectV1Schema,
    argumentsDigest: sha256DigestV1Schema,
    payloadBytes: z.number().int().nonnegative().max(64 * 1024 * 1024),
    nonce: identifierV1Schema,
    requestedAt: utcTimestampV1Schema,
    callChain: z
      .object({
        callChainId: identifierV1Schema,
        parentRequestId: identifierV1Schema.nullable(),
        depth: z.number().int().nonnegative().max(64),
        delegationDepth: z.number().int().nonnegative().max(32)
      })
      .strict(),
    contentTrust: z.literal("UNTRUSTED"),
    credentialsExcluded: z.literal(true)
  })
  .strict()
  .superRefine((request, context) => {
    if (request.callChain.delegationDepth > request.callChain.depth) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "delegationDepth"],
        message: "Delegation depth cannot exceed total call depth"
      });
    }
    if ((request.callChain.depth === 0) !== (request.callChain.parentRequestId === null)) {
      context.addIssue({
        code: "custom",
        path: ["callChain", "parentRequestId"],
        message: "Only root calls may omit a parent request"
      });
    }
  });

const textContentV1Schema = z
  .object({ type: z.literal("text"), text: z.string().max(1_048_576) })
  .strict();
const binaryContentV1Schema = z
  .object({
    type: z.enum(["image", "audio"]),
    data: z.string().max(16 * 1024 * 1024),
    mimeType: z.string().trim().min(1).max(256)
  })
  .strict();
const resourceLinkContentV1Schema = z
  .object({
    type: z.literal("resource_link"),
    name: z.string().trim().min(1).max(256),
    uri: z.string().trim().min(1).max(2_048),
    description: z.string().max(16_384).nullable(),
    mimeType: z.string().trim().min(1).max(256).nullable()
  })
  .strict();
const embeddedResourceContentV1Schema = z
  .object({
    type: z.literal("resource"),
    resource: z.union([
      z
        .object({
          uri: z.string().trim().min(1).max(2_048),
          mimeType: z.string().trim().min(1).max(256).nullable(),
          text: z.string().max(1_048_576)
        })
        .strict(),
      z
        .object({
          uri: z.string().trim().min(1).max(2_048),
          mimeType: z.string().trim().min(1).max(256).nullable(),
          blob: z.string().max(16 * 1024 * 1024)
        })
        .strict()
    ])
  })
  .strict();

const rawResultContentV1Schema = z.union([
  textContentV1Schema,
  binaryContentV1Schema,
  resourceLinkContentV1Schema,
  embeddedResourceContentV1Schema
]);

export const rawToolResultV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    resultId: identifierV1Schema,
    provenanceId: identifierV1Schema,
    requestId: identifierV1Schema,
    protocolRequestId: z.union([
      z.string().min(1).max(128),
      z.number().int().nonnegative().max(Number.MAX_SAFE_INTEGER)
    ]),
    sessionId: identifierV1Schema,
    serverId: identifierV1Schema,
    routeId: identifierV1Schema,
    schemaDigest: sha256DigestV1Schema,
    content: z.array(rawResultContentV1Schema).max(1_024),
    structuredContent: boundedProtocolJsonObjectV1Schema.nullable(),
    metadata: boundedProtocolJsonObjectV1Schema.nullable(),
    isError: z.boolean(),
    payloadBytes: z.number().int().nonnegative().max(64 * 1024 * 1024),
    contentDigest: sha256DigestV1Schema,
    contentTrust: z.literal("UNTRUSTED"),
    receivedAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((result, context) => {
    if (result.content.length === 0 && result.structuredContent === null) {
      context.addIssue({
        code: "custom",
        path: ["content"],
        message: "A raw result must contain content or structured content"
      });
    }
  });

export const gatewayErrorV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    errorId: identifierV1Schema,
    requestId: identifierV1Schema.nullable(),
    sessionId: identifierV1Schema.nullable(),
    origin: z.enum([
      "BOUNDARY",
      "IDENTITY",
      "PROTOCOL",
      "ROUTE",
      "POLICY",
      "APPROVAL",
      "DOWNSTREAM",
      "RESULT_GUARD",
      "PERSISTENCE",
      "INTERNAL"
    ]),
    code: capabilityIdentifierV1Schema,
    safeMessage: safeDisplayTextV1Schema,
    retryable: z.boolean(),
    possiblePartialEffects: z.boolean(),
    detailsDigest: sha256DigestV1Schema.nullable(),
    downstreamContentSuppressed: z.literal(true),
    occurredAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((error, context) => {
    if (error.possiblePartialEffects && error.requestId === null) {
      context.addIssue({
        code: "custom",
        path: ["requestId"],
        message: "Possible partial effects require a request binding"
      });
    }
  });

const awarenessAlternativeV1Schema = z
  .object({
    alternativeId: identifierV1Schema,
    summary: safeDisplayTextV1Schema,
    routeId: identifierV1Schema.nullable(),
    disposition: z.enum(["AVAILABLE", "REQUIRES_APPROVAL", "NOT_AVAILABLE", "DENIED"]),
    reasonCodes: z.array(capabilityIdentifierV1Schema).min(1).max(32)
  })
  .strict();

export const awarenessV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    awarenessId: identifierV1Schema,
    requestId: identifierV1Schema,
    sessionId: identifierV1Schema,
    actionId: identifierV1Schema,
    decisionId: identifierV1Schema,
    decision: z.enum([
      "DENY",
      "REQUIRE_APPROVAL",
      "SANDBOX",
      "ALLOW_WITH_CONSTRAINTS"
    ]),
    tier: z.number().int().min(0).max(3),
    factualSummary: safeDisplayTextV1Schema,
    reasonCodes: z.array(capabilityIdentifierV1Schema).min(1).max(128),
    coverage: coverageStateV1Schema,
    missingGuarantees: z.array(capabilityIdentifierV1Schema).max(64),
    alternatives: z.array(awarenessAlternativeV1Schema).min(1).max(32),
    generatedFromCanonicalData: z.literal(true),
    generatedAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((awareness, context) => {
    const alternativeIds = awareness.alternatives.map(
      (alternative) => alternative.alternativeId
    );
    if (new Set(alternativeIds).size !== alternativeIds.length) {
      context.addIssue({
        code: "custom",
        path: ["alternatives"],
        message: "Awareness alternative IDs must be unique"
      });
    }
    if (
      awareness.coverage !== "ENFORCED" &&
      awareness.missingGuarantees.length === 0
    ) {
      context.addIssue({
        code: "custom",
        path: ["missingGuarantees"],
        message: "Non-enforced coverage must identify at least one missing guarantee"
      });
    }
  });

const versionedBoundaryEnvelopeVariants = [
  z.object({ kind: z.literal("gateway-client"), payload: gatewayClientV1Schema }).strict(),
  z.object({ kind: z.literal("gateway-session"), payload: gatewaySessionV1Schema }).strict(),
  z
    .object({ kind: z.literal("downstream-server"), payload: downstreamServerV1Schema })
    .strict(),
  z.object({ kind: z.literal("tool-route"), payload: toolRouteV1Schema }).strict(),
  z.object({ kind: z.literal("discovery-result"), payload: discoveryResultV1Schema }).strict(),
  z.object({ kind: z.literal("tool-call-request"), payload: toolCallRequestV1Schema }).strict(),
  z.object({ kind: z.literal("raw-tool-result"), payload: rawToolResultV1Schema }).strict(),
  z.object({ kind: z.literal("gateway-error"), payload: gatewayErrorV1Schema }).strict(),
  z.object({ kind: z.literal("canonical-action"), payload: canonicalActionV1Schema }).strict(),
  z.object({ kind: z.literal("policy-decision"), payload: policyDecisionV1Schema }).strict(),
  z.object({ kind: z.literal("approval"), payload: approvalV1Schema }).strict(),
  z
    .object({ kind: z.literal("downstream-provenance"), payload: downstreamProvenanceV1Schema })
    .strict(),
  z.object({ kind: z.literal("governed-result"), payload: downstreamResultV1Schema }).strict(),
  z.object({ kind: z.literal("execution-outcome"), payload: executionOutcomeV1Schema }).strict(),
  z.object({ kind: z.literal("awareness"), payload: awarenessV1Schema }).strict()
] as const;

export const versionedBoundaryEnvelopeV1Schema = z.discriminatedUnion(
  "kind",
  versionedBoundaryEnvelopeVariants
);

export type DiscoveryResultV1 = z.infer<typeof discoveryResultV1Schema>;
export type ToolCallRequestV1 = z.infer<typeof toolCallRequestV1Schema>;
export type RawToolResultV1 = z.infer<typeof rawToolResultV1Schema>;
export type GatewayErrorV1 = z.infer<typeof gatewayErrorV1Schema>;
export type AwarenessV1 = z.infer<typeof awarenessV1Schema>;
export type VersionedBoundaryEnvelopeV1 = z.infer<
  typeof versionedBoundaryEnvelopeV1Schema
>;

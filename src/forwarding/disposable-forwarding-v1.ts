import { randomUUID } from "node:crypto";

import { z } from "zod";

import {
  computeCanonicalDigestV1,
  computeCanonicalJsonByteLengthV1
} from "../action-normalizer/canonical-action-v1.js";
import {
  approvedForwardingAuthorizationV1Schema,
  type ApprovedForwardingAuthorizationV1
} from "../approval/disposable-approval-v1.js";
import {
  boundedProtocolJsonObjectV1Schema,
  gatewayErrorV1Schema,
  rawToolResultV1Schema,
  toolCallRequestV1Schema,
  untrustedProtocolJsonShapeGuardV1Schema,
  type GatewayErrorV1,
  type RawToolResultV1,
  type ToolCallRequestV1
} from "../contracts/boundary-v1.js";
import {
  canonicalActionV1Schema,
  downstreamProvenanceV1Schema,
  downstreamResultV1Schema,
  type CanonicalActionV1
} from "../contracts/trajectory-v1.js";
import {
  downstreamServerRouteBindingV1Schema,
  identifierV1Schema,
  type DownstreamServerRouteBindingV1
} from "../contracts/v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema,
  type AuthenticatedSessionIdentityBindingV1
} from "../identity/client-authentication-v1.js";
import type { DisposableCredentialVaultV1 } from "../identity/credential-vault-v1.js";
import {
  authenticatedDownstreamPrincipalV1Schema,
  type AuthenticatedDownstreamPrincipalV1
} from "../routing/downstream-registry-v1.js";

const classificationV1Schema = z.enum([
  "PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET", "CREDENTIAL", "UNKNOWN"
]);
const dispositionV1Schema = z.enum(["ALLOW", "REDACT", "DENY", "QUARANTINE"]);

const releasedToolResultV1Schema = z.object({
  content: rawToolResultV1Schema.shape.content,
  structuredContent: boundedProtocolJsonObjectV1Schema.nullable(),
  metadata: boundedProtocolJsonObjectV1Schema.nullable(),
  contentTrust: z.literal("UNTRUSTED"),
  instructionPolicy: z.literal("DATA_ONLY")
}).strict();

export const mediatedForwardingResultV1Schema = z.object({
  schemaVersion: z.literal("1.0.0"),
  forwardingAttemptId: identifierV1Schema,
  provenance: downstreamProvenanceV1Schema.nullable(),
  result: downstreamResultV1Schema.nullable(),
  release: releasedToolResultV1Schema.nullable(),
  error: gatewayErrorV1Schema.nullable(),
  trustEvidenceEligible: z.boolean()
}).strict().superRefine((outcome, context) => {
  if ((outcome.provenance === null) !== (outcome.result === null)) {
    context.addIssue({ code: "custom", message: "Result metadata requires provenance" });
  }
  if (outcome.release !== null &&
    (outcome.result === null || !["ALLOW", "REDACT"].includes(outcome.result.disposition))) {
    context.addIssue({ code: "custom", path: ["release"], message: "Only allowed results may be released" });
  }
  if (outcome.error !== null && outcome.release !== null) {
    context.addIssue({ code: "custom", path: ["release"], message: "Errors cannot release downstream content" });
  }
  if (outcome.trustEvidenceEligible &&
    (outcome.result?.resultKind !== "SUCCESS" || outcome.result.disposition !== "ALLOW")) {
    context.addIssue({ code: "custom", path: ["trustEvidenceEligible"], message: "Only unmodified allowed success may be trust evidence" });
  }
});

export type ResultClassificationV1 = z.infer<typeof classificationV1Schema>;
export type ResultDispositionV1 = z.infer<typeof dispositionV1Schema>;
export type MediatedForwardingResultV1 = z.infer<typeof mediatedForwardingResultV1Schema>;

export interface DisposableExactForwarderV1Options {
  readonly credentialVault: DisposableCredentialVaultV1;
  readonly resolveCurrentRoute: (
    authorization: ApprovedForwardingAuthorizationV1
  ) => unknown;
  readonly authenticateDownstream: (attempt: {
    readonly serverId: string;
    readonly authentication: string | undefined;
  }) => unknown;
  readonly validateOutputSchema: (input: {
    readonly binding: DownstreamServerRouteBindingV1;
    readonly content: RawToolResultV1["content"];
    readonly structuredContent: RawToolResultV1["structuredContent"];
  }) => boolean;
  readonly classifyResult: (rawResult: RawToolResultV1) => readonly ResultClassificationV1[];
  readonly evaluateEgress: (input: {
    readonly action: CanonicalActionV1;
    readonly classifications: readonly ResultClassificationV1[];
  }) => ResultDispositionV1;
  readonly knownSecretValues?: readonly string[];
  readonly sensitiveFieldNames?: readonly string[];
  readonly maxResultBytes?: number;
  readonly clock?: () => Date;
  readonly resultIdFactory?: () => string;
  readonly provenanceIdFactory?: () => string;
  readonly errorIdFactory?: () => string;
}

export class ForwardingDeniedV1 extends Error {
  public constructor() {
    super("Exact downstream forwarding denied");
    this.name = "ForwardingDeniedV1";
  }
}

interface ParsedMcpToolResultV1 {
  readonly content: RawToolResultV1["content"];
  readonly structuredContent: RawToolResultV1["structuredContent"];
  readonly metadata: RawToolResultV1["metadata"];
  readonly isError: boolean;
}

interface RedactionOutcomeV1 {
  readonly value: ParsedMcpToolResultV1;
  readonly fieldsRedacted: number;
}

const dispositionRank: Readonly<Record<ResultDispositionV1, number>> = {
  ALLOW: 0,
  REDACT: 1,
  DENY: 2,
  QUARANTINE: 3
};

function stricterDisposition(
  left: ResultDispositionV1,
  right: ResultDispositionV1
): ResultDispositionV1 {
  return dispositionRank[left] >= dispositionRank[right] ? left : right;
}

function identitiesMatch(
  action: CanonicalActionV1,
  session: AuthenticatedSessionIdentityBindingV1
): boolean {
  return action.sessionId === session.stateNamespace &&
    action.identity.userId === session.identity.userId &&
    action.identity.agentId === session.identity.agentId &&
    action.identity.clientId === session.identity.clientId &&
    action.identity.hostId === session.identity.hostId;
}

function routeMatches(
  authorization: ApprovedForwardingAuthorizationV1,
  action: CanonicalActionV1,
  request: ToolCallRequestV1,
  binding: DownstreamServerRouteBindingV1
): boolean {
  const route = binding.route;
  return binding.server.health.state === "HEALTHY" && route.status === "ACTIVE" &&
    authorization.requestId === action.requestId && authorization.actionId === action.actionId &&
    authorization.actionHash === action.actionHash && authorization.sessionId === action.sessionId &&
    authorization.serverId === route.serverId && authorization.routeId === route.routeId &&
    authorization.toolName === route.toolName &&
    authorization.schemaDigest === route.schemaIntegrity.registeredDigest &&
    authorization.credentialAudienceId === route.credentialAudienceId &&
    authorization.policyScopeId === route.policyScopeId &&
    authorization.resourcesDigest === action.resourcesDigest &&
    authorization.environment === action.environment &&
    authorization.dataFlowDigest === action.dataFlowDigest &&
    request.requestId === action.requestId && request.sessionId === action.sessionId &&
    request.route.serverId === route.serverId && request.route.routeId === route.routeId &&
    request.route.toolName === route.toolName && request.route.exposedName === route.exposedName &&
    request.route.schemaDigest === route.schemaIntegrity.registeredDigest &&
    request.route.credentialAudienceId === route.credentialAudienceId &&
    request.route.policyScopeId === route.policyScopeId &&
    request.callChain.callChainId === action.callChain.callChainId &&
    action.route.serverId === route.serverId && action.route.routeId === route.routeId &&
    action.route.toolName === route.toolName &&
    action.route.schemaDigest === route.schemaIntegrity.registeredDigest;
}

function parseToolResult(body: Uint8Array, protocolRequestId: string | number): ParsedMcpToolResultV1 {
  let candidate: unknown;
  try {
    candidate = JSON.parse(Buffer.from(body).toString("utf8"));
  } catch {
    throw new ForwardingDeniedV1();
  }
  if (!untrustedProtocolJsonShapeGuardV1Schema.safeParse(candidate).success ||
    candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    throw new ForwardingDeniedV1();
  }
  const envelope = candidate as Record<string, unknown>;
  if (envelope["jsonrpc"] !== "2.0" || envelope["id"] !== protocolRequestId ||
    "error" in envelope || !("result" in envelope)) {
    throw new ForwardingDeniedV1();
  }
  const parsed = z.object({
    content: rawToolResultV1Schema.shape.content.default([]),
    structuredContent: boundedProtocolJsonObjectV1Schema.nullable().default(null),
    _meta: boundedProtocolJsonObjectV1Schema.nullable().default(null),
    isError: z.boolean().default(false)
  }).strict().safeParse(envelope["result"]);
  if (!parsed.success ||
    (parsed.data.content.length === 0 && parsed.data.structuredContent === null)) {
    throw new ForwardingDeniedV1();
  }
  return {
    content: parsed.data.content,
    structuredContent: parsed.data.structuredContent,
    metadata: parsed.data._meta,
    isError: parsed.data.isError
  };
}

function redactValue(
  value: unknown,
  secrets: readonly string[],
  sensitiveNames: ReadonlySet<string>,
  fieldName: string | null = null
): { readonly value: unknown; readonly count: number } {
  if (fieldName !== null && sensitiveNames.has(
    fieldName.normalize("NFKC").toLowerCase().replaceAll(/[-_\s]/gu, "")
  )) {
    return { value: "[REDACTED]", count: 1 };
  }
  if (typeof value === "string") {
    let redacted = value;
    let count = 0;
    for (const secret of secrets) {
      if (secret.length > 0 && redacted.includes(secret)) {
        redacted = redacted.split(secret).join("[REDACTED]");
        count += 1;
      }
    }
    return { value: redacted, count };
  }
  if (Array.isArray(value)) {
    let count = 0;
    const entries = value.map((entry) => {
      const result = redactValue(entry, secrets, sensitiveNames);
      count += result.count;
      return result.value;
    });
    return { value: entries, count };
  }
  if (value !== null && typeof value === "object") {
    let count = 0;
    const entries = Object.entries(value as Record<string, unknown>).map(([key, entry]) => {
      const result = redactValue(entry, secrets, sensitiveNames, key);
      count += result.count;
      return [key, result.value] as const;
    });
    return { value: Object.fromEntries(entries), count };
  }
  return { value, count: 0 };
}

function stringLeafMatches(value: unknown, pattern: RegExp): boolean {
  if (typeof value === "string") return pattern.test(value.normalize("NFKC"));
  if (Array.isArray(value)) return value.some((entry) => stringLeafMatches(entry, pattern));
  if (value !== null && typeof value === "object") {
    return Object.entries(value as Record<string, unknown>).some(([key, entry]) =>
      pattern.test(key.normalize("NFKC")) || stringLeafMatches(entry, pattern));
  }
  return false;
}

const credentialPattern = /(?:\bbearer\s+[a-z0-9._~+/=-]{8,}|\bapi[\s_-]*key\s*[:=]\s*\S{4,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)/iu;
const instructionPattern = /(?:ignore\s+(?:all\s+)?(?:prior|previous)\s+instructions|\bsystem\s*:\s*|\b(?:execute|run|delete)\s+(?:the\s+)?(?:command|tool|everything)\b)/iu;

function redactResult(
  parsed: ParsedMcpToolResultV1,
  secrets: readonly string[],
  sensitiveNames: ReadonlySet<string>
): RedactionOutcomeV1 {
  const redacted = redactValue(parsed, secrets, sensitiveNames);
  return {
    value: redacted.value as ParsedMcpToolResultV1,
    fieldsRedacted: redacted.count
  };
}

/** Process-local test component. It is deliberately not wired to the MCP lifecycle app. */
export class DisposableExactForwarderV1 {
  readonly #options: DisposableExactForwarderV1Options;
  readonly #attempts = new Set<string>();
  readonly #maxResultBytes: number;
  readonly #sensitiveNames: ReadonlySet<string>;

  public constructor(options: DisposableExactForwarderV1Options) {
    if (typeof options.classifyResult !== "function" || typeof options.evaluateEgress !== "function") {
      throw new TypeError("Result classification and egress policy are required");
    }
    this.#options = options;
    this.#maxResultBytes = options.maxResultBytes ?? 8 * 1_024 * 1_024;
    if (!Number.isSafeInteger(this.#maxResultBytes) || this.#maxResultBytes <= 0 ||
      this.#maxResultBytes > 64 * 1_024 * 1_024) {
      throw new RangeError("Result limit must be between one byte and 64 MiB");
    }
    this.#sensitiveNames = new Set((options.sensitiveFieldNames ?? [
      "authorization", "password", "token", "api_key", "apikey", "secret"
    ]).map((entry) => entry.normalize("NFKC").toLowerCase().replaceAll(/[-_\s]/gu, "")));
  }

  public async execute(input: {
    readonly authorization: ApprovedForwardingAuthorizationV1;
    readonly action: CanonicalActionV1;
    readonly request: ToolCallRequestV1;
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly credentialLeaseId: string;
    readonly signal?: AbortSignal;
  }): Promise<MediatedForwardingResultV1> {
    const authorization = approvedForwardingAuthorizationV1Schema.parse(input.authorization);
    const action = canonicalActionV1Schema.parse(input.action);
    const request = toolCallRequestV1Schema.parse(input.request);
    const session = authenticatedSessionIdentityBindingV1Schema.parse(input.session);
    const binding = downstreamServerRouteBindingV1Schema.parse(
      this.#options.resolveCurrentRoute(authorization)
    );
    const { actionHash, ...actionHashInput } = action;
    if (actionHash !== computeCanonicalDigestV1(actionHashInput) ||
      request.argumentsDigest !== computeCanonicalDigestV1(request.arguments) ||
      request.payloadBytes !== computeCanonicalJsonByteLengthV1(request.arguments) ||
      action.arguments.digest !== request.argumentsDigest || !identitiesMatch(action, session) ||
      !routeMatches(authorization, action, request, binding) ||
      binding.server.transport.kind !== "STREAMABLE_HTTP" ||
      this.#attempts.has(authorization.forwardingAttemptId)) {
      throw new ForwardingDeniedV1();
    }
    this.#attempts.add(authorization.forwardingAttemptId);

    const bodyObject = {
      jsonrpc: "2.0",
      id: request.protocolRequestId,
      method: "tools/call",
      params: { name: binding.route.toolName, arguments: request.arguments }
    };
    const body = Buffer.from(JSON.stringify(bodyObject), "utf8");
    try {
      const response = await this.#options.credentialVault.sendMcpJsonWithLease(session, {
        leaseId: identifierV1Schema.parse(input.credentialLeaseId),
        credentialProfileId: binding.server.credentialAudience.credentialProfileId,
        audienceId: binding.route.credentialAudienceId,
        routeId: binding.route.routeId,
        endpoint: binding.server.transport.endpoint,
        body,
        maxResponseBytes: this.#maxResultBytes,
        ...(input.signal === undefined ? {} : { signal: input.signal })
      });
      if (response.status < 200 || response.status >= 300 ||
        response.contentType?.toLowerCase().startsWith("application/json") !== true) {
        return this.#transportError(authorization, action, "downstream.invalid_response", true);
      }
      const principal = authenticatedDownstreamPrincipalV1Schema.parse(
        this.#options.authenticateDownstream({
          serverId: binding.server.serverId,
          authentication: response.downstreamAuthentication
        })
      );
      if (principal.serverId !== binding.server.serverId ||
        principal.principalId !== binding.server.authenticatedPrincipalId) {
        return this.#transportError(authorization, action, "downstream.identity_mismatch", true);
      }
      return this.#mediate({ authorization, action, request, binding, principal, responseBody: response.body });
    } catch (error) {
      if (error instanceof ForwardingDeniedV1) {
        return this.#transportError(authorization, action, "downstream.protocol_error", true);
      }
      if (input.signal?.aborted === true) {
        return this.#transportError(authorization, action, "downstream.cancelled", true);
      }
      if (error instanceof RangeError) {
        return this.#transportError(authorization, action, "result_guard.size_exceeded", true);
      }
      return this.#transportError(authorization, action, "downstream.transport_failure", true);
    }
  }

  #mediate(input: {
    readonly authorization: ApprovedForwardingAuthorizationV1;
    readonly action: CanonicalActionV1;
    readonly request: ToolCallRequestV1;
    readonly binding: DownstreamServerRouteBindingV1;
    readonly principal: AuthenticatedDownstreamPrincipalV1;
    readonly responseBody: Uint8Array;
  }): MediatedForwardingResultV1 {
    const parsed = parseToolResult(input.responseBody, input.request.protocolRequestId);
    const now = (this.#options.clock?.() ?? new Date()).toISOString();
    const provenanceId = identifierV1Schema.parse(this.#options.provenanceIdFactory?.() ?? randomUUID());
    const resultId = identifierV1Schema.parse(this.#options.resultIdFactory?.() ?? randomUUID());
    const provenance = downstreamProvenanceV1Schema.parse({
      schemaVersion: "1.0.0",
      provenanceId,
      requestId: input.request.requestId,
      actionId: input.action.actionId,
      sessionId: input.action.sessionId,
      callChainId: input.request.callChain.callChainId,
      serverId: input.principal.serverId,
      authenticatedPrincipalId: input.principal.principalId,
      routeId: input.binding.route.routeId,
      toolName: input.binding.route.toolName,
      schemaDigest: input.binding.route.schemaIntegrity.registeredDigest,
      transportEvidenceDigest: computeCanonicalDigestV1({
        forwardingAttemptId: input.authorization.forwardingAttemptId,
        serverId: input.principal.serverId,
        principalId: input.principal.principalId,
        identityRevision: input.principal.identityRevision,
        transport: input.binding.server.transport
      }),
      receivedAt: now,
      contentTrust: "UNTRUSTED"
    });
    const rawResult = rawToolResultV1Schema.parse({
      schemaVersion: "1.0.0",
      resultId,
      provenanceId,
      requestId: input.request.requestId,
      protocolRequestId: input.request.protocolRequestId,
      sessionId: input.action.sessionId,
      serverId: input.principal.serverId,
      routeId: input.binding.route.routeId,
      schemaDigest: input.binding.route.schemaIntegrity.registeredDigest,
      content: parsed.content,
      structuredContent: parsed.structuredContent,
      metadata: parsed.metadata,
      isError: parsed.isError,
      payloadBytes: input.responseBody.byteLength,
      contentDigest: computeCanonicalDigestV1(parsed),
      contentTrust: "UNTRUSTED",
      receivedAt: now
    });

    let schemaValid = false;
    let classifications: ResultClassificationV1[] = ["PUBLIC"];
    try {
      schemaValid = this.#options.validateOutputSchema({
        binding: input.binding,
        content: rawResult.content,
        structuredContent: rawResult.structuredContent
      });
      classifications = [...new Set(
        this.#options.classifyResult(rawResult)
          .map((entry) => classificationV1Schema.parse(entry))
      )];
      if (classifications.length === 0) classifications = ["UNKNOWN"];
    } catch {
      schemaValid = false;
      classifications = ["UNKNOWN"];
    }
    const redacted = redactResult(parsed, this.#options.knownSecretValues ?? [], this.#sensitiveNames);
    const structuralCredentialDetected = stringLeafMatches(parsed, credentialPattern);
    const instructionLikeContentDetected = stringLeafMatches(parsed, instructionPattern);
    if (redacted.fieldsRedacted > 0 && !classifications.includes("CREDENTIAL")) {
      classifications.push("CREDENTIAL");
    }
    if (structuralCredentialDetected && !classifications.includes("CREDENTIAL")) {
      classifications.push("CREDENTIAL");
    }
    let disposition: ResultDispositionV1 = schemaValid ? "ALLOW" : "QUARANTINE";
    if (rawResult.isError) disposition = stricterDisposition(disposition, "DENY");
    if (redacted.fieldsRedacted > 0) disposition = stricterDisposition(disposition, "REDACT");
    try {
      disposition = stricterDisposition(disposition, dispositionV1Schema.parse(
        this.#options.evaluateEgress({ action: input.action, classifications })
      ));
    } catch {
      disposition = "QUARANTINE";
    }
    if ((classifications.includes("SECRET") || classifications.includes("CREDENTIAL")) &&
      redacted.fieldsRedacted === 0) {
      disposition = stricterDisposition(disposition, "QUARANTINE");
    }
    if (disposition === "REDACT" && redacted.fieldsRedacted === 0) {
      disposition = "DENY";
    }
    const released = disposition === "ALLOW" || disposition === "REDACT"
      ? redacted.value
      : null;
    const markers = [
      "downstream.content.untrusted",
      "downstream.instructions.data_only",
      ...(parsed.metadata === null ? [] : ["downstream.metadata.untrusted"]),
      ...(parsed.content.some((entry) => entry.type === "resource" || entry.type === "resource_link")
        ? ["downstream.resource_content.untrusted"] : []),
      ...(instructionLikeContentDetected ? ["downstream.instruction_like_content.detected"] : []),
      ...(structuralCredentialDetected ? ["downstream.credential_pattern.detected"] : [])
    ];
    const redactionApplied = disposition === "REDACT" && redacted.fieldsRedacted > 0;
    const result = downstreamResultV1Schema.parse({
      schemaVersion: "1.0.0",
      resultId,
      provenanceId,
      requestId: input.request.requestId,
      actionId: input.action.actionId,
      sessionId: input.action.sessionId,
      serverId: input.principal.serverId,
      routeId: input.binding.route.routeId,
      resultKind: rawResult.isError ? "TOOL_ERROR" : "SUCCESS",
      mediaType: "application/json",
      byteLength: input.responseBody.byteLength,
      contentDigest: rawResult.contentDigest,
      schemaValidation: schemaValid ? "VALID" : "INVALID",
      schemaDigest: input.binding.route.schemaIntegrity.registeredDigest,
      classifications,
      redaction: {
        state: redactionApplied ? "APPLIED" : "NONE",
        fieldsRedacted: redactionApplied ? redacted.fieldsRedacted : 0,
        evidenceDigest: computeCanonicalDigestV1({
          sourceDigest: rawResult.contentDigest,
          fieldsRedacted: redacted.fieldsRedacted
        })
      },
      untrustedContentMarkers: markers,
      disposition,
      processedAt: now
    });
    const error = rawResult.isError
      ? this.#safeError(input.authorization, input.action, "downstream.tool_error", false)
      : disposition === "DENY" || disposition === "QUARANTINE"
        ? this.#safeError(input.authorization, input.action, "result_guard.content_withheld", false)
        : null;
    return mediatedForwardingResultV1Schema.parse({
      schemaVersion: "1.0.0",
      forwardingAttemptId: input.authorization.forwardingAttemptId,
      provenance,
      result,
      release: released === null ? null : {
        content: released.content,
        structuredContent: released.structuredContent,
        metadata: released.metadata,
        contentTrust: "UNTRUSTED",
        instructionPolicy: "DATA_ONLY"
      },
      error,
      trustEvidenceEligible: result.resultKind === "SUCCESS" && result.disposition === "ALLOW" &&
        !instructionLikeContentDetected
    });
  }

  #transportError(
    authorization: ApprovedForwardingAuthorizationV1,
    action: CanonicalActionV1,
    code: string,
    possiblePartialEffects: boolean
  ): MediatedForwardingResultV1 {
    return mediatedForwardingResultV1Schema.parse({
      schemaVersion: "1.0.0",
      forwardingAttemptId: authorization.forwardingAttemptId,
      provenance: null,
      result: null,
      release: null,
      error: this.#safeError(authorization, action, code, possiblePartialEffects),
      trustEvidenceEligible: false
    });
  }

  #safeError(
    authorization: ApprovedForwardingAuthorizationV1,
    action: CanonicalActionV1,
    code: string,
    possiblePartialEffects: boolean
  ): GatewayErrorV1 {
    return gatewayErrorV1Schema.parse({
      schemaVersion: "1.0.0",
      errorId: this.#options.errorIdFactory?.() ?? randomUUID(),
      requestId: action.requestId,
      sessionId: action.sessionId,
      origin: code.startsWith("result_guard") ? "RESULT_GUARD" : "DOWNSTREAM",
      code,
      safeMessage: possiblePartialEffects
        ? "The downstream operation did not return a confirmed safe result; partial effects are possible."
        : "The downstream result was withheld by the gateway.",
      retryable: false,
      possiblePartialEffects,
      detailsDigest: computeCanonicalDigestV1({
        forwardingAttemptId: authorization.forwardingAttemptId,
        code
      }),
      downstreamContentSuppressed: true,
      occurredAt: (this.#options.clock?.() ?? new Date()).toISOString()
    });
  }
}

import { createHash, randomUUID } from "node:crypto";

import { z } from "zod";

import {
  boundedProtocolJsonObjectV1Schema,
  discoveryResultV1Schema,
  type DiscoveryResultV1
} from "../contracts/boundary-v1.js";
import {
  capabilityIdentifierV1Schema,
  downstreamServerRouteBindingV1Schema,
  downstreamServerShapeV1Schema,
  downstreamServerV1Schema,
  identifierV1Schema,
  toolRouteV1Schema,
  toolRouteShapeV1Schema,
  utcTimestampV1Schema,
  type DownstreamServerRouteBindingV1,
  type DownstreamServerV1,
  type ToolRouteV1
} from "../contracts/v1.js";
import {
  authenticatedSessionIdentityBindingV1Schema,
  type AuthenticatedSessionIdentityBindingV1
} from "../identity/client-authentication-v1.js";

const authenticationMethodV1Schema = z.enum([
  "MUTUAL_TLS",
  "LOCAL_PROCESS_ATTESTATION",
  "SIGNED_TOKEN",
  "TEST_FIXTURE"
]);
const environmentV1Schema = z.enum([
  "DEVELOPMENT",
  "TEST",
  "STAGING",
  "PRODUCTION",
  "UNKNOWN"
]);
const uniqueCapabilitiesV1Schema = z
  .array(capabilityIdentifierV1Schema)
  .max(128)
  .superRefine((capabilities, context) => {
    if (new Set(capabilities).size !== capabilities.length) {
      context.addIssue({ code: "custom", message: "Capabilities must be unique" });
    }
  });

export const routeAdministratorAuthorityV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    administratorId: identifierV1Schema,
    role: z.literal("ROUTE_REGISTRAR"),
    authenticatedAt: utcTimestampV1Schema
  })
  .strict();

export const authenticatedDownstreamPrincipalV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    serverId: identifierV1Schema,
    principalId: identifierV1Schema,
    authenticationMethod: authenticationMethodV1Schema,
    credentialId: identifierV1Schema,
    identityRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    authenticatedAt: utcTimestampV1Schema
  })
  .strict();

const serverRegistrationV1Schema = downstreamServerShapeV1Schema.omit({
  capabilityIntegrity: true,
  health: true,
  registration: true
});
const routeRegistrationV1Schema = toolRouteShapeV1Schema
  .omit({ schemaIntegrity: true, status: true, registeredAt: true })
  .extend({
    inputSchema: boundedProtocolJsonObjectV1Schema,
    outputSchema: boundedProtocolJsonObjectV1Schema.nullable()
  })
  .strict();

export const downstreamRegistrationV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    server: serverRegistrationV1Schema,
    routes: z.array(routeRegistrationV1Schema).min(1).max(1_000),
    registrationRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER)
  })
  .strict()
  .superRefine((registration, context) => {
    const routeIds = new Set<string>();
    const toolNames = new Set<string>();
    const exposedKeys = new Set<string>();
    for (const [index, route] of registration.routes.entries()) {
      if (route.serverId !== registration.server.serverId) {
        context.addIssue({
          code: "custom",
          path: ["routes", index, "serverId"],
          message: "Registered routes must belong to the registered server"
        });
      }
      if (route.credentialAudienceId !== registration.server.credentialAudience.audienceId) {
        context.addIssue({
          code: "custom",
          path: ["routes", index, "credentialAudienceId"],
          message: "Registered routes must use the server credential audience"
        });
      }
      if (routeIds.has(route.routeId) || toolNames.has(route.toolName)) {
        context.addIssue({
          code: "custom",
          path: ["routes", index],
          message: "Route identifiers and server tool names must be unique"
        });
      }
      routeIds.add(route.routeId);
      toolNames.add(route.toolName);
      const exposedKey = [
        route.policyScopeId,
        route.environment,
        route.exposedName.toLowerCase()
      ].join("\u0000");
      if (exposedKeys.has(exposedKey)) {
        context.addIssue({
          code: "custom",
          path: ["routes", index, "exposedName"],
          message: "Exposed route names must be unambiguous within scope and environment"
        });
      }
      exposedKeys.add(exposedKey);
    }
  });

const observedToolV1Schema = z
  .object({
    name: capabilityIdentifierV1Schema,
    title: z.string().trim().min(1).max(256).nullable(),
    description: z.string().max(16_384).nullable(),
    inputSchema: boundedProtocolJsonObjectV1Schema,
    outputSchema: boundedProtocolJsonObjectV1Schema.nullable(),
    annotations: boundedProtocolJsonObjectV1Schema.nullable()
  })
  .strict();

export const downstreamDiscoveryObservationV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    mcpProtocolVersion: z.string().regex(/^\d{4}-\d{2}-\d{2}$/u),
    capabilities: uniqueCapabilitiesV1Schema,
    tools: z.array(observedToolV1Schema).max(1_000),
    observedAt: utcTimestampV1Schema
  })
  .strict()
  .superRefine((observation, context) => {
    const names = observation.tools.map((tool) => tool.name);
    if (new Set(names).size !== names.length) {
      context.addIssue({ code: "custom", message: "Observed tool names must be unique" });
    }
  });

export const downstreamRegistryAuditEventV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    eventId: identifierV1Schema,
    eventType: z.enum([
      "SERVER_REGISTERED",
      "DISCOVERY_VERIFIED",
      "DISCOVERY_QUARANTINED",
      "QUARANTINE_REVIEWED",
      "SERVER_UNAVAILABLE",
      "ROUTE_INTEGRITY_VERIFIED",
      "ROUTE_INTEGRITY_QUARANTINED",
      "ROUTE_RESOLVED",
      "ROUTE_DENIED"
    ]),
    serverId: identifierV1Schema,
    routeId: identifierV1Schema.nullable(),
    actorId: identifierV1Schema,
    evidenceDigest: z.string().regex(/^[a-f0-9]{64}$/u),
    reasonCodes: z.array(capabilityIdentifierV1Schema).max(32),
    occurredAt: utcTimestampV1Schema
  })
  .strict();

export type RouteAdministratorAuthorityV1 = z.infer<
  typeof routeAdministratorAuthorityV1Schema
>;
export type AuthenticatedDownstreamPrincipalV1 = z.infer<
  typeof authenticatedDownstreamPrincipalV1Schema
>;
export type DownstreamRegistrationV1 = z.infer<typeof downstreamRegistrationV1Schema>;
export type DownstreamDiscoveryObservationV1 = z.infer<
  typeof downstreamDiscoveryObservationV1Schema
>;
export type DownstreamRegistryAuditEventV1 = z.infer<
  typeof downstreamRegistryAuditEventV1Schema
>;

export interface DownstreamAuthenticationAttemptV1 {
  readonly serverId: string;
  readonly authorizationHeader: string | undefined;
}

export type DownstreamAuthenticatorV1 = (
  attempt: DownstreamAuthenticationAttemptV1
) => unknown;

export interface RouteAuthorizationContextV1 {
  readonly stage: "DISCOVERY" | "CALL_TIME";
  readonly session: AuthenticatedSessionIdentityBindingV1;
  readonly server: DownstreamServerV1;
  readonly route: ToolRouteV1;
}

export type RouteAuthorizerV1 = (context: RouteAuthorizationContextV1) => boolean;

export class DownstreamRegistryDeniedV1 extends Error {
  public constructor() {
    super("Downstream registry operation denied");
    this.name = "DownstreamRegistryDeniedV1";
  }
}

interface StoredRouteV1 {
  contract: ToolRouteV1;
  readonly expectedInputSchema: Record<string, unknown>;
  readonly expectedOutputSchema: Record<string, unknown> | null;
  observedTool: z.infer<typeof observedToolV1Schema> | null;
}

interface StoredServerV1 {
  contract: DownstreamServerV1;
  readonly routes: Map<string, StoredRouteV1>;
  quarantineLatched: boolean;
}

export interface DisposableDownstreamRegistryV1Options {
  readonly administratorAuthorizer: (authority: RouteAdministratorAuthorityV1) => boolean;
  readonly downstreamAuthenticator: DownstreamAuthenticatorV1;
  readonly routeAuthorizer: RouteAuthorizerV1;
  readonly clock?: () => Date;
  readonly eventIdFactory?: () => string;
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => canonicalJson(entry)).join(",")}]`;
  }
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function computeRegistryDigestV1(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function routeKey(route: Pick<ToolRouteV1, "policyScopeId" | "environment" | "exposedName">): string {
  return [route.policyScopeId, route.environment, route.exposedName.toLowerCase()].join("\u0000");
}

/** Disposable registry for automated tests; it is not a production persistence fallback. */
export class DisposableDownstreamRegistryV1 {
  readonly #options: DisposableDownstreamRegistryV1Options;
  readonly #servers = new Map<string, StoredServerV1>();
  readonly #routeIds = new Set<string>();
  readonly #routeKeys = new Set<string>();
  readonly #audit: DownstreamRegistryAuditEventV1[] = [];

  public constructor(options: DisposableDownstreamRegistryV1Options) {
    this.#options = options;
  }

  public register(
    authorityInput: RouteAdministratorAuthorityV1,
    registrationInput: DownstreamRegistrationV1
  ): DownstreamServerV1 {
    const authority = routeAdministratorAuthorityV1Schema.parse(authorityInput);
    if (!this.#options.administratorAuthorizer(authority)) {
      throw new DownstreamRegistryDeniedV1();
    }
    const registration = downstreamRegistrationV1Schema.parse(registrationInput);
    if (this.#servers.has(registration.server.serverId)) {
      throw new DownstreamRegistryDeniedV1();
    }
    for (const route of registration.routes) {
      if (this.#routeIds.has(route.routeId) || this.#routeKeys.has(routeKey(route))) {
        throw new DownstreamRegistryDeniedV1();
      }
    }

    const now = this.#options.clock?.() ?? new Date();
    const registeredSurface = {
      mcpProtocolVersion: registration.server.mcpProtocolVersion,
      capabilities: [...registration.server.capabilities].sort(),
      toolNames: registration.routes.map((route) => route.toolName).sort()
    };
    const surfaceDigest = computeRegistryDigestV1(registeredSurface);
    const evidenceDigest = computeRegistryDigestV1(registration);
    const server = downstreamServerV1Schema.parse({
      ...registration.server,
      capabilityIntegrity: {
        registeredDigest: surfaceDigest,
        observedDigest: null,
        state: "UNVERIFIED",
        observedAt: null
      },
      health: {
        state: "QUARANTINED",
        checkedAt: now.toISOString(),
        reasonCodes: ["discovery.unverified"]
      },
      registration: {
        source: registration.server.authenticationMethod === "TEST_FIXTURE"
          ? "TEST_FIXTURE"
          : "ADMIN_CONFIG",
        registeredBy: authority.administratorId,
        registeredAt: now.toISOString(),
        revision: registration.registrationRevision,
        evidenceDigest
      }
    });
    const routes = new Map<string, StoredRouteV1>();
    for (const registeredRoute of registration.routes) {
      const {
        inputSchema: expectedInputSchema,
        outputSchema: expectedOutputSchema,
        ...routeFields
      } = registeredRoute;
      const route = toolRouteV1Schema.parse({
        ...routeFields,
        schemaIntegrity: {
          registeredDigest: computeRegistryDigestV1({
            inputSchema: expectedInputSchema,
            outputSchema: expectedOutputSchema
          }),
          observedDigest: null,
          state: "UNVERIFIED",
          observedAt: null
        },
        status: "QUARANTINED",
        registeredAt: now.toISOString()
      });
      routes.set(route.routeId, {
        contract: route,
        expectedInputSchema: structuredClone(expectedInputSchema),
        expectedOutputSchema: structuredClone(expectedOutputSchema),
        observedTool: null
      });
    }

    this.#servers.set(server.serverId, { contract: server, routes, quarantineLatched: false });
    for (const route of routes.values()) {
      this.#routeIds.add(route.contract.routeId);
      this.#routeKeys.add(routeKey(route.contract));
    }
    this.#record("SERVER_REGISTERED", server.serverId, null, authority.administratorId,
      evidenceDigest, []);
    return structuredClone(server);
  }

  public observeDiscovery(
    attempt: DownstreamAuthenticationAttemptV1,
    observationInput: DownstreamDiscoveryObservationV1
  ): DownstreamServerV1 {
    const stored = this.#servers.get(attempt.serverId);
    if (stored === undefined) {
      throw new DownstreamRegistryDeniedV1();
    }
    let principalCandidate: unknown;
    try {
      principalCandidate = this.#options.downstreamAuthenticator(attempt);
    } catch {
      throw new DownstreamRegistryDeniedV1();
    }
    const principalResult = authenticatedDownstreamPrincipalV1Schema.safeParse(principalCandidate);
    if (!principalResult.success) {
      throw new DownstreamRegistryDeniedV1();
    }
    const principal = principalResult.data;
    if (
      principal.serverId !== stored.contract.serverId ||
      principal.principalId !== stored.contract.authenticatedPrincipalId ||
      principal.authenticationMethod !== stored.contract.authenticationMethod
    ) {
      throw new DownstreamRegistryDeniedV1();
    }
    const observation = downstreamDiscoveryObservationV1Schema.parse(observationInput);
    const observedTools = new Map(observation.tools.map((tool) => [tool.name, tool]));
    const observedSurface = {
      mcpProtocolVersion: observation.mcpProtocolVersion,
      capabilities: [...observation.capabilities].sort(),
      toolNames: observation.tools.map((tool) => tool.name).sort()
    };
    const surfaceDigest = computeRegistryDigestV1(observedSurface);
    const surfaceVerified =
      surfaceDigest === stored.contract.capabilityIntegrity.registeredDigest;
    if (!surfaceVerified) {
      stored.quarantineLatched = true;
    }
    const reasonCodes = surfaceVerified ? [] : ["discovery.surface_drift"];

    stored.contract = downstreamServerV1Schema.parse({
      ...stored.contract,
      capabilityIntegrity: {
        ...stored.contract.capabilityIntegrity,
        observedDigest: surfaceDigest,
        state: surfaceVerified ? "VERIFIED" : "DRIFTED",
        observedAt: observation.observedAt
      },
      health: {
        state: surfaceVerified && !stored.quarantineLatched ? "HEALTHY" : "QUARANTINED",
        checkedAt: observation.observedAt,
        reasonCodes
      }
    });

    for (const route of stored.routes.values()) {
      const tool = observedTools.get(route.contract.toolName) ?? null;
      const observedDigest = tool === null ? null : computeRegistryDigestV1({
        inputSchema: tool.inputSchema,
        outputSchema: tool.outputSchema
      });
      const schemaDigestVerified =
        observedDigest !== null &&
        observedDigest === route.contract.schemaIntegrity.registeredDigest;
      if (!schemaDigestVerified) {
        stored.quarantineLatched = true;
      }
      const routeActive = surfaceVerified && schemaDigestVerified && !stored.quarantineLatched;
      route.contract = toolRouteV1Schema.parse({
        ...route.contract,
        schemaIntegrity: {
          ...route.contract.schemaIntegrity,
          observedDigest,
          state: observedDigest === null
            ? "UNVERIFIED"
            : schemaDigestVerified ? "VERIFIED" : "DRIFTED",
          observedAt: observedDigest === null ? null : observation.observedAt
        },
        status: routeActive ? "ACTIVE" : "QUARANTINED"
      });
      route.observedTool = tool === null ? null : structuredClone(tool);
      this.#record(
        schemaDigestVerified ? "ROUTE_INTEGRITY_VERIFIED" : "ROUTE_INTEGRITY_QUARANTINED",
        stored.contract.serverId,
        route.contract.routeId,
        principal.principalId,
        observedDigest ?? computeRegistryDigestV1("missing-schema"),
        schemaDigestVerified ? [] : ["route.schema_drift"]
      );
    }

    if (stored.quarantineLatched) {
      stored.contract = downstreamServerV1Schema.parse({
        ...stored.contract,
        health: {
          state: "QUARANTINED",
          checkedAt: observation.observedAt,
          reasonCodes: ["discovery.review_required"]
        }
      });
      for (const route of stored.routes.values()) {
        route.contract = toolRouteV1Schema.parse({ ...route.contract, status: "QUARANTINED" });
      }
    }

    const eventType = surfaceVerified && [...stored.routes.values()].every(
      (route) => route.contract.status === "ACTIVE"
    ) ? "DISCOVERY_VERIFIED" : "DISCOVERY_QUARANTINED";
    const evidenceDigest = computeRegistryDigestV1({ principal, observation });
    this.#record(eventType, stored.contract.serverId, null, principal.principalId,
      evidenceDigest, eventType === "DISCOVERY_VERIFIED" ? [] : ["discovery.drift"]);
    return structuredClone(stored.contract);
  }

  public markServerUnavailable(
    authorityInput: RouteAdministratorAuthorityV1,
    serverIdInput: string,
    reasonCodeInput: string
  ): DownstreamServerV1 {
    const authority = routeAdministratorAuthorityV1Schema.parse(authorityInput);
    if (!this.#options.administratorAuthorizer(authority)) {
      throw new DownstreamRegistryDeniedV1();
    }
    const serverId = identifierV1Schema.parse(serverIdInput);
    const reasonCode = capabilityIdentifierV1Schema.parse(reasonCodeInput);
    const stored = this.#servers.get(serverId);
    if (stored === undefined) {
      throw new DownstreamRegistryDeniedV1();
    }
    const now = this.#options.clock?.() ?? new Date();
    const verified = stored.contract.capabilityIntegrity.state === "VERIFIED";
    stored.contract = downstreamServerV1Schema.parse({
      ...stored.contract,
      health: {
        state: verified ? "UNAVAILABLE" : "QUARANTINED",
        checkedAt: now.toISOString(),
        reasonCodes: [reasonCode]
      }
    });
    for (const route of stored.routes.values()) {
      route.contract = toolRouteV1Schema.parse({
        ...route.contract,
        status: route.contract.schemaIntegrity.state === "VERIFIED"
          ? "UNAVAILABLE"
          : "QUARANTINED"
      });
    }
    this.#record("SERVER_UNAVAILABLE", serverId, null, authority.administratorId,
      computeRegistryDigestV1({ serverId, reasonCode }), [reasonCode]);
    return structuredClone(stored.contract);
  }

  public reviewQuarantine(
    authorityInput: RouteAdministratorAuthorityV1,
    serverIdInput: string
  ): DownstreamServerV1 {
    const authority = routeAdministratorAuthorityV1Schema.parse(authorityInput);
    if (!this.#options.administratorAuthorizer(authority)) {
      throw new DownstreamRegistryDeniedV1();
    }
    const serverId = identifierV1Schema.parse(serverIdInput);
    const stored = this.#servers.get(serverId);
    if (
      stored === undefined ||
      !stored.quarantineLatched ||
      stored.contract.capabilityIntegrity.state !== "VERIFIED" ||
      [...stored.routes.values()].some((route) =>
        route.observedTool === null || route.contract.schemaIntegrity.state !== "VERIFIED"
      )
    ) {
      throw new DownstreamRegistryDeniedV1();
    }
    const now = this.#options.clock?.() ?? new Date();
    stored.quarantineLatched = false;
    stored.contract = downstreamServerV1Schema.parse({
      ...stored.contract,
      health: { state: "HEALTHY", checkedAt: now.toISOString(), reasonCodes: [] }
    });
    for (const route of stored.routes.values()) {
      route.contract = toolRouteV1Schema.parse({ ...route.contract, status: "ACTIVE" });
    }
    this.#record("QUARANTINE_REVIEWED", serverId, null, authority.administratorId,
      computeRegistryDigestV1({
        server: stored.contract,
        routes: [...stored.routes.values()].map((route) => route.contract)
      }), []);
    return structuredClone(stored.contract);
  }

  public discover(request: {
    readonly requestId: string;
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly policyScopeId: string;
    readonly environment: z.infer<typeof environmentV1Schema>;
  }): DiscoveryResultV1 {
    const session = authenticatedSessionIdentityBindingV1Schema.parse(request.session);
    const requestId = identifierV1Schema.parse(request.requestId);
    const policyScopeId = identifierV1Schema.parse(request.policyScopeId);
    const environment = environmentV1Schema.parse(request.environment);
    const tools: DiscoveryResultV1["tools"] = [];
    for (const stored of this.#servers.values()) {
      if (stored.contract.health.state !== "HEALTHY") {
        continue;
      }
      for (const route of stored.routes.values()) {
        if (
          route.contract.status !== "ACTIVE" ||
          route.contract.policyScopeId !== policyScopeId ||
          route.contract.environment !== environment ||
          route.observedTool === null ||
          !this.#authorize("DISCOVERY", session, stored.contract, route.contract)
        ) {
          continue;
        }
        tools.push({
          route: {
            serverId: route.contract.serverId,
            routeId: route.contract.routeId,
            toolName: route.contract.toolName,
            exposedName: route.contract.exposedName,
            schemaDigest: route.contract.schemaIntegrity.registeredDigest,
            credentialAudienceId: route.contract.credentialAudienceId,
            policyScopeId: route.contract.policyScopeId
          },
          title: route.observedTool.title,
          description: route.observedTool.description,
          inputSchema: structuredClone(route.observedTool.inputSchema),
          outputSchema: structuredClone(route.observedTool.outputSchema),
          annotations: structuredClone(route.observedTool.annotations),
          availability: "AVAILABLE",
          contentTrust: "UNTRUSTED",
          callTimeAuthorizationRequired: true
        });
      }
    }
    tools.sort((left, right) => left.route.exposedName.localeCompare(right.route.exposedName));
    return discoveryResultV1Schema.parse({
      schemaVersion: "1.0.0",
      requestId,
      sessionId: session.stateNamespace,
      policyScopeId,
      environment,
      tools,
      coverage: "UNPROTECTED",
      generatedAt: (this.#options.clock?.() ?? new Date()).toISOString()
    });
  }

  public resolveCall(request: {
    readonly session: AuthenticatedSessionIdentityBindingV1;
    readonly policyScopeId: string;
    readonly environment: z.infer<typeof environmentV1Schema>;
    readonly exposedName: string;
  }): DownstreamServerRouteBindingV1 {
    const session = authenticatedSessionIdentityBindingV1Schema.parse(request.session);
    const lookupKey = routeKey({
      policyScopeId: identifierV1Schema.parse(request.policyScopeId),
      environment: environmentV1Schema.parse(request.environment),
      exposedName: capabilityIdentifierV1Schema.parse(request.exposedName)
    });
    for (const stored of this.#servers.values()) {
      for (const route of stored.routes.values()) {
        if (routeKey(route.contract) !== lookupKey) {
          continue;
        }
        if (
          stored.contract.health.state !== "HEALTHY" ||
          route.contract.status !== "ACTIVE" ||
          !this.#authorize("CALL_TIME", session, stored.contract, route.contract)
        ) {
          this.#record("ROUTE_DENIED", stored.contract.serverId, route.contract.routeId,
            session.identity.clientId, computeRegistryDigestV1(lookupKey), ["route.denied"]);
          throw new DownstreamRegistryDeniedV1();
        }
        const binding = downstreamServerRouteBindingV1Schema.parse({
          server: stored.contract,
          route: route.contract
        });
        this.#record("ROUTE_RESOLVED", stored.contract.serverId, route.contract.routeId,
          session.identity.clientId, computeRegistryDigestV1(binding), []);
        return structuredClone(binding);
      }
    }
    throw new DownstreamRegistryDeniedV1();
  }

  public readAudit(
    authorityInput: RouteAdministratorAuthorityV1
  ): readonly DownstreamRegistryAuditEventV1[] {
    const authority = routeAdministratorAuthorityV1Schema.parse(authorityInput);
    if (!this.#options.administratorAuthorizer(authority)) {
      throw new DownstreamRegistryDeniedV1();
    }
    return structuredClone(this.#audit);
  }

  #authorize(
    stage: RouteAuthorizationContextV1["stage"],
    session: AuthenticatedSessionIdentityBindingV1,
    server: DownstreamServerV1,
    route: ToolRouteV1
  ): boolean {
    try {
      return this.#options.routeAuthorizer({ stage, session, server, route });
    } catch {
      return false;
    }
  }

  #record(
    eventType: DownstreamRegistryAuditEventV1["eventType"],
    serverId: string,
    routeId: string | null,
    actorId: string,
    evidenceDigest: string,
    reasonCodes: string[]
  ): void {
    this.#audit.push(downstreamRegistryAuditEventV1Schema.parse({
      schemaVersion: "1.0.0",
      eventId: this.#options.eventIdFactory?.() ?? randomUUID(),
      eventType,
      serverId,
      routeId,
      actorId,
      evidenceDigest,
      reasonCodes,
      occurredAt: (this.#options.clock?.() ?? new Date()).toISOString()
    }));
  }
}

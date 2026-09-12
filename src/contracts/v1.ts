import { z } from "zod";

const identifierV1 = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9._:-]*[A-Za-z0-9])?$/u);

const capabilityIdentifierV1 = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[a-z][a-z0-9._/-]*$/u);

const protocolVersionV1 = z.string().regex(/^\d{4}-\d{2}-\d{2}$/u);
const utcTimestampV1 = z.iso.datetime();
const sha256DigestV1 = z.string().regex(/^[a-f0-9]{64}$/u);

export const identifierV1Schema = identifierV1;
export const capabilityIdentifierV1Schema = capabilityIdentifierV1;
export const utcTimestampV1Schema = utcTimestampV1;
export const sha256DigestV1Schema = sha256DigestV1;

const uniqueCapabilityIdentifiersV1 = z
  .array(capabilityIdentifierV1)
  .max(128)
  .superRefine((capabilities, context) => {
    if (new Set(capabilities).size !== capabilities.length) {
      context.addIssue({
        code: "custom",
        message: "Capability identifiers must be unique"
      });
    }
  });

const integrityObservationV1Schema = z
  .object({
    registeredDigest: sha256DigestV1,
    observedDigest: sha256DigestV1.nullable(),
    state: z.enum(["VERIFIED", "UNVERIFIED", "DRIFTED"]),
    observedAt: utcTimestampV1.nullable()
  })
  .strict()
  .superRefine((integrity, context) => {
    if (integrity.observedDigest === null) {
      if (integrity.state !== "UNVERIFIED" || integrity.observedAt !== null) {
        context.addIssue({
          code: "custom",
          message: "Missing observations must remain UNVERIFIED without a timestamp"
        });
      }
      return;
    }

    if (integrity.observedAt === null) {
      context.addIssue({
        code: "custom",
        path: ["observedAt"],
        message: "Observed digests require an observation timestamp"
      });
    }

    const expectedState =
      integrity.registeredDigest === integrity.observedDigest ? "VERIFIED" : "DRIFTED";
    if (integrity.state !== expectedState) {
      context.addIssue({
        code: "custom",
        path: ["state"],
        message: `Digest comparison requires ${expectedState} integrity state`
      });
    }
  });

const downstreamEndpointV1 = z
  .url()
  .max(2_048)
  .superRefine((endpoint, context) => {
    const parsed = new URL(endpoint);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      context.addIssue({
        code: "custom",
        message: "Downstream endpoints must use HTTPS or loopback HTTP"
      });
    }

    if (parsed.username !== "" || parsed.password !== "") {
      context.addIssue({
        code: "custom",
        message: "Downstream endpoints cannot embed credentials"
      });
    }

    if (parsed.search !== "" || parsed.hash !== "") {
      context.addIssue({
        code: "custom",
        message: "Downstream endpoints cannot include query strings or fragments"
      });
    }

    const loopbackHosts = new Set(["localhost", "127.0.0.1", "[::1]"]);
    if (parsed.protocol === "http:" && !loopbackHosts.has(parsed.hostname.toLowerCase())) {
      context.addIssue({
        code: "custom",
        message: "Plain HTTP is allowed only for loopback endpoints"
      });
    }
  });

export const coverageStateV1Schema = z.enum([
  "ENFORCED",
  "DEGRADED",
  "OBSERVE_ONLY",
  "UNPROTECTED"
]);

export const gatewayClientV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    userId: identifierV1,
    agentId: identifierV1,
    clientId: identifierV1,
    host: z
      .object({
        hostId: identifierV1,
        name: z.string().trim().min(1).max(128),
        version: z.string().trim().min(1).max(64)
      })
      .strict(),
    mcpProtocolVersion: protocolVersionV1,
    capabilities: uniqueCapabilityIdentifiersV1.max(32),
    issuedAt: utcTimestampV1
  })
  .strict();

export const gatewaySessionQuotaLimitsV1Schema = z
  .object({
    callsPerMinute: z.number().int().positive().max(100_000),
    concurrentCalls: z.number().int().positive().max(1_000),
    payloadBytes: z.number().int().positive().max(64 * 1024 * 1024),
    callDepth: z.number().int().nonnegative().max(64),
    delegationDepth: z.number().int().nonnegative().max(32)
  })
  .strict();

export const gatewaySessionV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    sessionId: identifierV1,
    identity: z
      .object({
        userId: identifierV1,
        agentId: identifierV1,
        clientId: identifierV1,
        hostId: identifierV1
      })
      .strict(),
    stateNamespace: identifierV1,
    status: z.enum(["INITIALIZING", "ACTIVE", "QUARANTINED", "CLOSING", "CLOSED"]),
    coverage: coverageStateV1Schema,
    quotaLimits: gatewaySessionQuotaLimitsV1Schema,
    createdAt: utcTimestampV1,
    lastActivityAt: utcTimestampV1,
    expiresAt: utcTimestampV1
  })
  .strict()
  .superRefine((session, context) => {
    const createdAt = Date.parse(session.createdAt);
    const lastActivityAt = Date.parse(session.lastActivityAt);
    const expiresAt = Date.parse(session.expiresAt);

    if (lastActivityAt < createdAt) {
      context.addIssue({
        code: "custom",
        path: ["lastActivityAt"],
        message: "lastActivityAt cannot precede createdAt"
      });
    }

    if (expiresAt <= createdAt) {
      context.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "expiresAt must be later than createdAt"
      });
    }

    if (lastActivityAt > expiresAt) {
      context.addIssue({
        code: "custom",
        path: ["lastActivityAt"],
        message: "lastActivityAt cannot be later than expiresAt"
      });
    }
  });

const downstreamTransportV1Schema = z.discriminatedUnion("kind", [
  z
    .object({
      kind: z.literal("STDIO"),
      launchProfileId: identifierV1
    })
    .strict(),
  z
    .object({
      kind: z.literal("STREAMABLE_HTTP"),
      endpoint: downstreamEndpointV1,
      authenticationProfileId: identifierV1
    })
    .strict(),
  z
    .object({
      kind: z.literal("SSE"),
      endpoint: downstreamEndpointV1,
      authenticationProfileId: identifierV1
    })
    .strict()
]);

export const downstreamServerShapeV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    serverId: identifierV1,
    displayName: z.string().trim().min(1).max(128),
    authenticatedPrincipalId: identifierV1,
    authenticationMethod: z.enum([
      "MUTUAL_TLS",
      "LOCAL_PROCESS_ATTESTATION",
      "SIGNED_TOKEN",
      "TEST_FIXTURE"
    ]),
    mcpProtocolVersion: protocolVersionV1,
    transport: downstreamTransportV1Schema,
    credentialAudience: z
      .object({
        audienceId: identifierV1,
        credentialProfileId: identifierV1
      })
      .strict(),
    capabilities: uniqueCapabilityIdentifiersV1,
    capabilityIntegrity: integrityObservationV1Schema,
    health: z
      .object({
        state: z.enum(["HEALTHY", "DEGRADED", "UNAVAILABLE", "QUARANTINED"]),
        checkedAt: utcTimestampV1,
        reasonCodes: uniqueCapabilityIdentifiersV1.max(32)
      })
      .strict(),
    registration: z
      .object({
        source: z.enum(["ADMIN_CONFIG", "SIGNED_MANIFEST", "TEST_FIXTURE"]),
        registeredBy: identifierV1,
        registeredAt: utcTimestampV1,
        revision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
        evidenceDigest: sha256DigestV1
      })
      .strict()
  })
  .strict();

export const downstreamServerV1Schema = downstreamServerShapeV1Schema.superRefine(
  (server, context) => {
    if (
      server.capabilityIntegrity.state !== "VERIFIED" &&
      server.health.state !== "QUARANTINED"
    ) {
      context.addIssue({
        code: "custom",
        path: ["health", "state"],
        message: "Unverified or drifted capabilities require a quarantined server"
      });
    }

    const registeredAt = Date.parse(server.registration.registeredAt);
    if (
      server.capabilityIntegrity.observedAt !== null &&
      Date.parse(server.capabilityIntegrity.observedAt) < registeredAt
    ) {
      context.addIssue({
        code: "custom",
        path: ["capabilityIntegrity", "observedAt"],
        message: "Capability observations cannot predate server registration"
      });
    }

    if (Date.parse(server.health.checkedAt) < registeredAt) {
      context.addIssue({
        code: "custom",
        path: ["health", "checkedAt"],
        message: "Health observations cannot predate server registration"
      });
    }
  }
);

export const toolRouteShapeV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    routeId: identifierV1,
    serverId: identifierV1,
    toolName: capabilityIdentifierV1,
    exposedName: capabilityIdentifierV1,
    credentialAudienceId: identifierV1,
    policyScopeId: identifierV1,
    environment: z.enum(["DEVELOPMENT", "TEST", "STAGING", "PRODUCTION", "UNKNOWN"]),
    resourceMapping: z
      .object({
        resourceClass: z.enum([
          "FILESYSTEM",
          "SHELL",
          "GIT",
          "PACKAGE",
          "NETWORK",
          "DATABASE",
          "CLOUD",
          "BROWSER",
          "PROCESS",
          "DEPLOYMENT",
          "UNKNOWN"
        ]),
        resolverId: identifierV1,
        scope: z.string().trim().min(1).max(512)
      })
      .strict(),
    schemaIntegrity: integrityObservationV1Schema,
    status: z.enum(["ACTIVE", "UNAVAILABLE", "QUARANTINED", "DISABLED"]),
    registeredAt: utcTimestampV1
  })
  .strict();

export const toolRouteV1Schema = toolRouteShapeV1Schema.superRefine((route, context) => {
    if (route.schemaIntegrity.state !== "VERIFIED" && route.status !== "QUARANTINED") {
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "Unverified or drifted tool schemas require a quarantined route"
      });
    }

    if (route.environment === "UNKNOWN" && route.status === "ACTIVE") {
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "Routes with unknown environments cannot be active"
      });
    }

    if (route.resourceMapping.resourceClass === "UNKNOWN" && route.status === "ACTIVE") {
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "Routes with unknown resource classes cannot be active"
      });
    }

    if (
      route.schemaIntegrity.observedAt !== null &&
      Date.parse(route.schemaIntegrity.observedAt) < Date.parse(route.registeredAt)
    ) {
      context.addIssue({
        code: "custom",
        path: ["schemaIntegrity", "observedAt"],
        message: "Schema observations cannot predate route registration"
      });
    }
  });

export const downstreamServerRouteBindingV1Schema = z
  .object({
    server: downstreamServerV1Schema,
    route: toolRouteV1Schema
  })
  .strict()
  .superRefine((binding, context) => {
    if (binding.route.serverId !== binding.server.serverId) {
      context.addIssue({
        code: "custom",
        path: ["route", "serverId"],
        message: "Route serverId must match its bound downstream server"
      });
    }

    if (
      binding.route.credentialAudienceId !== binding.server.credentialAudience.audienceId
    ) {
      context.addIssue({
        code: "custom",
        path: ["route", "credentialAudienceId"],
        message: "Route credential audience must match its downstream server"
      });
    }

    if (binding.route.status === "ACTIVE" && binding.server.health.state !== "HEALTHY") {
      context.addIssue({
        code: "custom",
        path: ["route", "status"],
        message: "Active routes require a healthy downstream server"
      });
    }
  });

export const toolRouteSetV1Schema = z
  .array(toolRouteV1Schema)
  .max(10_000)
  .superRefine((routes, context) => {
    const routeIds = new Set<string>();
    const exposedRouteKeys = new Set<string>();

    routes.forEach((route, index) => {
      if (routeIds.has(route.routeId)) {
        context.addIssue({
          code: "custom",
          path: [index, "routeId"],
          message: "Route IDs must be unique"
        });
      }
      routeIds.add(route.routeId);

      const exposedRouteKey = [
        route.policyScopeId,
        route.environment,
        route.exposedName.toLowerCase()
      ].join(":");
      if (exposedRouteKeys.has(exposedRouteKey)) {
        context.addIssue({
          code: "custom",
          path: [index, "exposedName"],
          message: "Exposed tool names must be unambiguous within a scope and environment"
        });
      }
      exposedRouteKeys.add(exposedRouteKey);
    });
  });

export type CoverageStateV1 = z.infer<typeof coverageStateV1Schema>;
export type GatewayClientV1 = z.infer<typeof gatewayClientV1Schema>;
export type GatewaySessionQuotaLimitsV1 = z.infer<
  typeof gatewaySessionQuotaLimitsV1Schema
>;
export type GatewaySessionV1 = z.infer<typeof gatewaySessionV1Schema>;
export type DownstreamServerV1 = z.infer<typeof downstreamServerV1Schema>;
export type ToolRouteV1 = z.infer<typeof toolRouteV1Schema>;
export type DownstreamServerRouteBindingV1 = z.infer<
  typeof downstreamServerRouteBindingV1Schema
>;

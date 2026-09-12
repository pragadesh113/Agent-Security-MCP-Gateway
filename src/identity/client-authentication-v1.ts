import { createHash } from "node:crypto";

import { z } from "zod";

import { identifierV1Schema, utcTimestampV1Schema } from "../contracts/v1.js";

const authenticationMethodV1Schema = z.enum([
  "MUTUAL_TLS",
  "LOCAL_PEER_CREDENTIAL",
  "SIGNED_TOKEN",
  "TEST_FIXTURE"
]);

export const authenticatedClientPrincipalV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    userId: identifierV1Schema,
    agentId: identifierV1Schema,
    clientId: identifierV1Schema,
    host: z
      .object({
        hostId: identifierV1Schema,
        name: z.string().trim().min(1).max(128),
        version: z.string().trim().min(1).max(64)
      })
      .strict(),
    authentication: z
      .object({
        method: authenticationMethodV1Schema,
        credentialId: identifierV1Schema,
        identityRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
        authenticatedAt: utcTimestampV1Schema
      })
      .strict()
  })
  .strict();

const transportSessionIdV1Schema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._~-]+$/u);

export const authenticatedSessionIdentityBindingV1Schema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    transportSessionId: transportSessionIdV1Schema,
    stateNamespace: identifierV1Schema,
    identity: z
      .object({
        userId: identifierV1Schema,
        agentId: identifierV1Schema,
        clientId: identifierV1Schema,
        hostId: identifierV1Schema,
        authenticationMethod: authenticationMethodV1Schema,
        credentialId: identifierV1Schema,
        identityRevision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER)
      })
      .strict()
  })
  .strict();

export type AuthenticatedClientPrincipalV1 = z.infer<
  typeof authenticatedClientPrincipalV1Schema
>;
export type AuthenticatedSessionIdentityBindingV1 = z.infer<
  typeof authenticatedSessionIdentityBindingV1Schema
>;

export interface ClientAuthenticationAttemptV1 {
  readonly transport: "STREAMABLE_HTTP";
  readonly remoteAddress: string;
  readonly authorizationHeader: string | undefined;
  readonly trustedTlsPeer: {
    readonly schemaVersion: "1.0.0";
    readonly authorized: boolean;
    readonly authorizationError: string | null;
    readonly protocol: string | null;
    readonly certificate: {
      readonly fingerprintSha256: string | undefined;
      readonly validFrom: string | undefined;
      readonly validTo: string | undefined;
      readonly extendedKeyUsageOids: readonly string[];
    };
  } | null;
}

export type ClientAuthenticatorV1 = (
  attempt: ClientAuthenticationAttemptV1
) => unknown;

export function bindAuthenticatedIdentityToSessionV1(
  principalInput: AuthenticatedClientPrincipalV1,
  transportSessionId: string
): AuthenticatedSessionIdentityBindingV1 {
  const principal = authenticatedClientPrincipalV1Schema.parse(principalInput);
  const namespaceDigest = createHash("sha256")
    .update(transportSessionId, "utf8")
    .digest("hex");

  return authenticatedSessionIdentityBindingV1Schema.parse({
    schemaVersion: "1.0.0",
    transportSessionId,
    stateNamespace: `session:${namespaceDigest}`,
    identity: {
      userId: principal.userId,
      agentId: principal.agentId,
      clientId: principal.clientId,
      hostId: principal.host.hostId,
      authenticationMethod: principal.authentication.method,
      credentialId: principal.authentication.credentialId,
      identityRevision: principal.authentication.identityRevision
    }
  });
}

export function principalMatchesSessionBindingV1(
  principalInput: AuthenticatedClientPrincipalV1,
  bindingInput: AuthenticatedSessionIdentityBindingV1
): boolean {
  const principal = authenticatedClientPrincipalV1Schema.parse(principalInput);
  const binding = authenticatedSessionIdentityBindingV1Schema.parse(bindingInput);

  return principal.userId === binding.identity.userId &&
    principal.agentId === binding.identity.agentId &&
    principal.clientId === binding.identity.clientId &&
    principal.host.hostId === binding.identity.hostId &&
    principal.authentication.method === binding.identity.authenticationMethod &&
    principal.authentication.credentialId === binding.identity.credentialId &&
    principal.authentication.identityRevision === binding.identity.identityRevision;
}

export function principalHasSameSubjectV1(
  principalInput: AuthenticatedClientPrincipalV1,
  bindingInput: AuthenticatedSessionIdentityBindingV1
): boolean {
  const principal = authenticatedClientPrincipalV1Schema.parse(principalInput);
  const binding = authenticatedSessionIdentityBindingV1Schema.parse(bindingInput);

  return principal.userId === binding.identity.userId &&
    principal.agentId === binding.identity.agentId &&
    principal.clientId === binding.identity.clientId &&
    principal.host.hostId === binding.identity.hostId &&
    principal.authentication.method === binding.identity.authenticationMethod;
}
